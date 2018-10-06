//
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// proxy
//
// The proxy registers an NNG listener for surveys at a predefined
// ZeroTier address, which the workers must dial into.  This lets it
// get the list of connected workers.
//
// The proxy periodically issues a survey, which tells it where workers
// can be contacted; it builds a list of these.  (For now we're using
// a dumb linked list, in the future this should be a hash table for
// performance reasons.)
//
// The proxy *also* sets up an HTTP REST server.  This server will
// answer requests, servicing them by sending messages to the remote
// workers (based on the URL given).
//
// Note that for scalability reasons, we might not want to always
// keep an open REQ socket to every worker -- the reason for this
// is that we might have vast numbers of workers, and each REQ would
// require us to keep a separate underlying TCP connection open.
//
// We could add caching of these connections at a later date.
//

#include <nng/nng.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>
#include <nng/transport/zerotier/zerotier.h>

#include <mbedtls/base64.h>

#include <ctype.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cfgfile.h"
#include "object.h"
#include "rpc.h"

#ifndef CONFIG
#define CONFIG "proxy.cfg"
#endif

nng_mtx *lock;

nng_cv * survcv;
nng_mtx *survlk;

nng_socket      reqsock;
nng_socket      survsock;
char *          survurl;
char *          httpurl;
char *          zthome;
char *          static_uri;
char *          static_dir;
nng_tls_config *tls = NULL;

typedef struct controller controller;

struct controller {
	controller * next;
	uint64_t     nodeid;
	char *       name;
	nng_sockaddr sa;    // address for its worker
	nng_time     stamp; // when it last responded to a survey
	nng_socket   reqsock;
	nng_pipe     survpipe; // survey pipe that created it
	char         url[128];
};

controller *controllers;

typedef struct context context;
struct context {
	context *   next;    // free list link
	nng_aio *   httpaio; // HTTP aio.
	nng_aio *   reqaio;  // low level reqaio (including connect)
	nng_ctx     reqctx;
	nng_msg *   reqmsg; // request msg
	int         state;
	controller *cp;
};

void
add_controller(nng_sockaddr sa, const char *name, nng_pipe p)
{
	controller *cp;
	nng_dialer *dialer;
	nng_mtx_lock(lock);
	for (cp = controllers; cp != NULL; cp = cp->next) {
		if ((strcmp(cp->name, name) == 0) &&
		    (sa.s_zt.sa_port == cp->sa.s_zt.sa_port) &&
		    (sa.s_zt.sa_nodeid == cp->sa.s_zt.sa_nodeid) &&
		    (sa.s_zt.sa_nwid == cp->sa.s_zt.sa_nwid)) {
			cp->sa       = sa;
			cp->stamp    = nng_clock();
			cp->survpipe = p;
			nng_mtx_unlock(lock);
			return;
		}
	}
	if ((cp = calloc(1, sizeof(*cp))) == NULL) {
		nng_mtx_unlock(lock);
		return;
	}

	if ((cp->name = strdup(name)) == NULL) {
		nng_mtx_unlock(lock);
		free(cp);
		return;
	}
	cp->sa       = sa;
	cp->next     = controllers;
	cp->stamp    = nng_clock();
	cp->survpipe = p;
	snprintf(cp->url, sizeof(cp->url), "zt://%llx.%llx:%llu",
	    (unsigned long long) sa.s_zt.sa_nodeid,
	    (unsigned long long) sa.s_zt.sa_nwid,
	    (unsigned long long) sa.s_zt.sa_port);

	if (nng_req0_open(&cp->reqsock) != 0) {
		nng_mtx_unlock(lock);
		free(cp->name);
		free(cp);
		return;
	}

	if ((nng_setopt_ms(cp->reqsock, NNG_OPT_RECONNMINT, 1) != 0) ||
	    (nng_setopt_ms(cp->reqsock, NNG_OPT_RECONNMAXT, 1000) != 0) ||
	    (nng_setopt_ms(cp->reqsock, NNG_OPT_REQ_RESENDTIME, 1000) != 0) ||
	    (nng_setopt_ms(cp->reqsock, NNG_OPT_ZT_PING_TIME, 1000) != 0) ||
	    (nng_setopt_ms(cp->reqsock, NNG_OPT_ZT_CONN_TIME, 1000) != 0) ||
	    (nng_dial(cp->reqsock, cp->url, NULL, NNG_FLAG_NONBLOCK) != 0)) {
		nng_mtx_unlock(lock);
		nng_close(cp->reqsock);
		free(cp->name);
		free(cp);
		return;
	}
	controllers = cp;

	printf("Adding %s served by %s\n", cp->name, cp->url);

	nng_mtx_unlock(lock);
}

// This just prunes any controllers that have not had a survey response
// in the given stale time.
void
prune_controllers(nng_time stale)
{
	nng_time     now = nng_clock();
	controller **cpp;
	controller * cp;
	now -= stale;

	nng_mtx_lock(lock);
	cpp = &controllers;
	while ((cp = *cpp) != NULL) {
		if ((cp->stamp + stale) >= nng_clock()) {
			cpp = &cp->next;
			continue;
		}
		// Stale, so remove it.
		printf("Pruning %s served by %s\n", cp->name, cp->url);

		nng_close(cp->reqsock);
		*cpp = cp->next;
		free(cp->name);
		free(cp);
	}
	nng_mtx_unlock(lock);
}

static nng_optspec opts[] = {
	{ "cfg", 'c', 'c', true },
};

static void
survey_pipe_cb(nng_pipe p, int ev, void *arg)
{
	// We actually don't care about the arguments for 	xnow.
	// Later we might actually want to print these.  We could also
	// apply a more aggressive pruning for peers that have dropped.
	(void) arg;

	if (ev == NNG_PIPE_EV_REM_POST) {
		controller *cp;
		nng_mtx_lock(lock);
		for (cp = controllers; cp != NULL; cp = cp->next) {
			if (nng_pipe_id(cp->survpipe) == nng_pipe_id(p)) {
				// Remote peer is removed, mark it stale.
				// This will force it to be reaped.  Note
				// that there can be more than one such.
				cp->stamp = 0;
			}
		}
		nng_mtx_unlock(lock);
	}
	nng_mtx_lock(survlk);
	nng_cv_wake(survcv);
	nng_mtx_unlock(survlk);
}

static void
survey_loop(void)
{
	nng_listener l;
	char *       urls;
	int          rv;

	if (((rv = nng_surveyor0_open(&survsock)) != 0) ||
	    ((rv = nng_pipe_notify(survsock, NNG_PIPE_EV_ADD_POST,
	          survey_pipe_cb, NULL)) != 0) ||
	    ((rv = nng_pipe_notify(survsock, NNG_PIPE_EV_REM_POST,
	          survey_pipe_cb, NULL)) != 0) ||
	    ((rv = nng_setopt_ms(
	          survsock, NNG_OPT_SURVEYOR_SURVEYTIME, 1000)) != 0) ||
	    ((rv = nng_setopt_ms(survsock, NNG_OPT_ZT_PING_TIME, 1000)) !=
	        0) ||
	    ((rv = nng_listener_create(&l, survsock, survurl)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	if (zthome != NULL) {
		rv = nng_listener_setopt_string(l, NNG_OPT_ZT_HOME, zthome);
		if (rv != 0) {
			fprintf(stderr, "ZT_HOME: %s\n", nng_strerror(rv));
			exit(1);
		}
	}

	if (((rv = nng_listener_start(l, 0)) != 0) ||
	    ((rv = nng_listener_getopt_string(l, NNG_OPT_URL, &urls)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	printf("SURVEYOR listening at %s\n", urls);

	for (;;) {
		nng_msg *msg;

		if (nng_msg_alloc(&msg, 0) != 0) {
			nng_msleep(1000); // try again in a second
			continue;
		}

		switch (nng_sendmsg(survsock, msg, 0)) {
		case 0:
			break;
		case NNG_ECLOSED:
			nng_msg_free(msg);
			return;
		default:
			nng_msg_free(msg);
			nng_msleep(1000); // try again in a second
			continue;
		}

		for (;;) {
			nng_sockaddr_zt ztsa;
			nng_sockaddr    peer;
			nng_pipe        pipe;
			char *          name;
			int             port;
			object *        obj;
			object *        arr;

			switch (nng_recvmsg(survsock, &msg, 0)) {
			case NNG_ETIMEDOUT:
			case NNG_ESTATE:
			default:
				// End of survey responses.
				goto endsurvey;
			case NNG_ECLOSED:
				return;
			case 0:
				break;
			}

			pipe = nng_msg_get_pipe(msg);
			if (nng_pipe_getopt_sockaddr(
			        pipe, NNG_OPT_REMADDR, &peer) != 0) {
				nng_msg_free(msg);
				fprintf(stderr, "Cannot get peer address\n");
				continue;
			}

			obj = parse_obj(nng_msg_body(msg), nng_msg_len(msg));
			nng_msg_free(msg);

			if ((obj == NULL) ||
			    (!get_obj_int(obj, "port", &port)) || (port < 1) ||
			    (port > 0xffffff) ||
			    (!get_obj_obj(obj, "controllers", &arr)) ||
			    (get_arr_len(arr) < 1)) {
				fprintf(stderr, "Malformed survey response\n");
				continue;
			}

			peer.s_zt.sa_port = port; // REP port is different!
			for (int i = 0; i < get_arr_len(arr); i++) {
				if (!get_arr_string(arr, i, &name)) {
					continue;
				}
				add_controller(peer, name, pipe);
			}
		}

	endsurvey:
		prune_controllers(30000); // Prune anything over 30 secs old
		nng_mtx_lock(survlk);
		// 10 seconds, or immediately on a pipe change.
		nng_cv_until(survcv, nng_clock() + 10000);
		nng_mtx_unlock(survlk);
		nng_msleep(200); // 200 msec for peer to settle.
	}
}

static void
rpcerr(nng_aio *aio, uint16_t code, const char *msg)
{
	nng_http_res *res = NULL;
	char          doc[256];
	int           rv;

	if (((rv = nng_http_res_alloc(&res)) != 0) ||
	    ((rv = nng_http_res_set_status(res, code)) != 0) ||
	    ((rv = nng_http_res_set_reason(res, msg)) != 0) ||
	    ((rv = nng_http_res_set_header(
	          res, "Content-Type", "application/json")) != 0)) {
		if (res != NULL) {
			nng_http_res_free(res);
		}
		nng_aio_finish(aio, rv);
		return;
	}

	// Message will be same as passed in, or HTTP default reason if NULL.
	snprintf(doc, sizeof(doc), "{ \"status\": %d, \"message\": \"%s\" }",
	    code, nng_http_res_get_reason(res));

	if ((rv = nng_http_res_copy_data(res, doc, strlen(doc))) != 0) {
		nng_http_res_free(res);
		nng_aio_finish(aio, rv);
		return;
	}
	nng_aio_set_output(aio, 0, res);
	nng_aio_finish(aio, 0);
}

static void
autherr(nng_aio *aio, const char *realm, const char *msg, int code)
{
	nng_http_res *res = NULL;
	char          auth[1024];
	char          doc[256];
	int           rv;

	snprintf(doc, sizeof(doc), "{ \"status\": %d, \"message\": \"%s\" }",
	    NNG_HTTP_STATUS_UNAUTHORIZED, msg);

	// Authentication errors require us to send 401 and a WWW-Authenticate
	// header.  We only advertise the "basic" realm.
	// Clients may send *either* a Bearer token, or basic (or basic + otp)
	// credentials.  If a one time password is required, then that
	// requires a

	if ((rv = nng_http_res_alloc(&res)) != 0) {
		nng_aio_finish(aio, rv);
		return;
	}
	if (((rv = nng_http_res_set_status(
	          res, NNG_HTTP_STATUS_UNAUTHORIZED)) != 0) ||
	    ((rv = nng_http_res_set_reason(res, msg)) != 0) ||
	    ((rv = nng_http_res_set_header(
	          res, "Content-Type", "application/json")) != 0) ||
	    ((rv = nng_http_res_copy_data(res, doc, strlen(doc))) != 0)) {

		nng_http_res_free(res);
		nng_aio_finish(aio, rv);
	}

	switch (code) {
	case E_AUTHREQD:
	case E_AUTHFAIL:
	default:
		snprintf(auth, sizeof(auth), "Basic realm=\"%s\"", realm);
		break;
	case E_AUTHEXPIRE:
	case E_AUTHTOKEN:
		snprintf(auth, sizeof(auth),
		    "Bearer realm=\"%s\", error=\"invalid_token\", "
		    "error_description=\"%s\"",
		    realm, msg);
		break;
	case E_AUTHOTP:
		// OTP extension. This indicates that a one time password
		// should be supplied with the Basic authentication.
		// We pick this up via a second HTTP Authorization header,
		// which will look like "Authorization: OTP <pin>"
		snprintf(auth, sizeof(auth),
		    "Basic realm=\"%s\", X-ZTC-OTP realm=\"%s\"", realm,
		    realm);
		break;
	}
	if ((rv = nng_http_res_set_header(res, "WWW-Authenticate", auth)) !=
	    0) {
		nng_http_res_free(res);
		nng_aio_finish(aio, rv);
		return;
	}

	nng_aio_set_output(aio, 0, res);
	nng_aio_finish(aio, 0);
}

static nng_mtx *   reaplock = NULL;
static nng_cv *    reapcv   = NULL;
static nng_thread *reapthr  = NULL;
static context *   reaplist = NULL;
static bool        reapexit = false;
static void        ctxreap(void *arg);

static void
ctxinit(void)
{
	int rv;
	if (((rv = nng_mtx_alloc(&reaplock)) != 0) ||
	    ((rv = nng_cv_alloc(&reapcv, reaplock)) != 0) ||
	    ((rv = nng_thread_create(&reapthr, ctxreap, NULL)) != 0)) {
		fprintf(stderr, "ctxinit: %s\n", nng_strerror(rv));
		exit(1);
	}
}

static void
ctxfini(void)
{
	nng_mtx_lock(reaplock);
	reapexit = true;
	nng_cv_wake(reapcv);
	nng_mtx_unlock(reaplock);
	nng_thread_destroy(reapthr);
	nng_cv_free(reapcv);
	nng_mtx_free(reaplock);
}

static void
ctxreap(void *arg)
{
	context *ctx;
	(void) arg;
	nng_mtx_lock(reaplock);
	for (;;) {
		while ((ctx = reaplist) != NULL) {
			reaplist = ctx->next;
			nng_mtx_unlock(reaplock);

			if (ctx->reqaio != NULL) {
				nng_aio_free(ctx->reqaio);
			}
			if (nng_ctx_id(ctx->reqctx) > 0) {
				nng_ctx_close(ctx->reqctx);
			}
			nng_mtx_lock(reaplock);
		}
		if (reapexit) {
			break;
		}
		nng_cv_wait(reapcv);
	}
	nng_mtx_unlock(reaplock);
}

void
freectx(context *ctx)
{
	if (ctx != NULL) {
		nng_mtx_lock(reaplock);
		ctx->next = reaplist;
		nng_cv_wake(reapcv);
		nng_mtx_unlock(reaplock);
	}
}

context *
getctx(controller *cp, void (*cb)(void *))
{
	context *ctx;
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL) {
		return (NULL);
	}

	if (nng_aio_alloc(&ctx->reqaio, cb, ctx) != 0) {
		freectx(ctx);
		return (NULL);
	}
	ctx->cp = cp;
	return (ctx);
}

static atomic_ullong req_id;

static void
rpc_cancel(nng_aio *aio, void *arg, int rv)
{
	context *ctx;
	nng_mtx_lock(lock);
	if (nng_aio_get_output(aio, 1) == aio) {
		nng_aio_set_output(aio, 1, NULL);
		nng_aio_cancel(ctx->reqaio);
	}
	nng_mtx_unlock(lock);
}

static void
rpc_cb(void *arg)
{
	context *     ctx = arg;
	nng_aio *     httpaio;
	nng_aio *     reqaio;
	nng_msg *     msg;
	object *      obj;
	object *      tobj;
	char *        str;
	char *        realm;
	nng_http_res *res;
	int           rv;

	nng_mtx_lock(lock);
	httpaio = ctx->httpaio;
	reqaio  = ctx->reqaio;

	if ((rv = nng_aio_result(reqaio)) != 0) {
		if ((msg = ctx->reqmsg) != NULL) {
			nng_msg_free(msg);
			ctx->reqmsg = NULL;
		}
		nng_aio_set_output(httpaio, 1, NULL);
		nng_aio_finish(httpaio, rv);
		freectx(ctx);
		nng_mtx_unlock(lock);
		return;
	}
	switch (ctx->state) {
	case 0:
		ctx->state  = 1;
		ctx->reqmsg = NULL;
		nng_ctx_recv(ctx->reqctx, ctx->reqaio);
		break;
	case 1:
		if (nng_aio_get_output(httpaio, 1) == NULL) {
			// canceled.
			nng_aio_finish(httpaio, NNG_ECANCELED);
			freectx(ctx);
			break;
		}
		nng_aio_set_output(httpaio, 1, NULL);
		msg = nng_aio_get_msg(ctx->reqaio);
		nng_aio_set_msg(ctx->reqaio, NULL);

		obj   = parse_obj(nng_msg_body(msg), nng_msg_len(msg));
		realm = ctx->cp->name;
		freectx(ctx);
		rv  = NNG_EPROTO;
		res = NULL;

		if (obj == NULL) {
			nng_aio_finish(httpaio, NNG_EPROTO);
			break;
		}

		if (get_obj_obj(obj, "error", &tobj)) {
			int   code;
			char *rsn = "unknown error";

			get_obj_string(tobj, "message", &rsn);
			if (get_obj_int(tobj, "code", &code)) {
				switch (code) {
				case E_AUTHREQD:
				case E_AUTHTOKEN:
				case E_AUTHEXPIRE:
				case E_AUTHFAIL:
				case E_AUTHOTP:
					autherr(httpaio, realm, rsn, code);
					break;
				default:
					if ((code < 100) || (code > 599)) {
						code = 500;
					}
					rpcerr(httpaio, code, rsn);
					break;
				}
			} else {
				rpcerr(httpaio, 500, rsn);
			}
			free_obj(obj);
			break;
		}

		if (!get_obj_obj(obj, "result", &tobj)) {
			rpcerr(httpaio, 500, "Bad JSON-RPC 2.0 reply");
			free_obj(obj);
			return;
		}

		if (((str = print_obj(tobj)) == NULL) ||
		    (nng_http_res_alloc(&res) != 0) ||
		    (nng_http_res_set_header(
		         res, "Content-Type", "application/json") != 0) ||
		    (nng_http_res_copy_data(res, str, strlen(str)) != 0)) {
			free(str);
			free_obj(obj);
			nng_aio_finish(httpaio, NNG_ENOMEM);
			break;
		}
		nng_http_res_set_status(res, 200);
		nng_http_res_set_reason(res, "OK");
		free_obj(obj);
		free(str);

		nng_aio_set_output(httpaio, 0, res);
		nng_aio_finish(httpaio, 0);
		break;
	default:
		break;
	}

	nng_mtx_unlock(lock);
}

static void
do_rpc(nng_aio *aio, controller *cp, const char *rpcmeth, object *params)
{
	unsigned long long rid;
	object *           obj;
	context *          ctx = NULL;
	char *             str = NULL;
	nng_msg *          msg = NULL;

	while ((rid = atomic_fetch_add(&req_id, 1)) == 0) {
	}

	if (((obj = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj, "jsonrpc", "2.0")) ||
	    (!add_obj_uint64(obj, "id", rid)) ||
	    (!add_obj_string(obj, "method", rpcmeth)) ||
	    (!add_obj_obj(obj, "params", params))) {
		free_obj(obj);
		free_obj(params);
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	if (((ctx = getctx(cp, rpc_cb)) == NULL) ||
	    (nng_ctx_open(&ctx->reqctx, cp->reqsock) != 0) ||
	    ((str = print_obj(obj)) == NULL) ||
	    (nng_msg_alloc(&msg, strlen(str)) != 0)) {
		// In theory ctx_open could have failed for some other
		// reason, but in practice only NNG_ENOMEM.
		freectx(ctx);
		free_obj(obj);
		free(str);
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	memcpy(nng_msg_body(msg), str, strlen(str));
	free(str);
	free_obj(obj);

	ctx->state   = 0;
	ctx->httpaio = aio;
	ctx->reqmsg  = msg;
	nng_aio_set_output(aio, 1, ctx); // Use this for now.
	nng_aio_defer(aio, rpc_cancel, ctx);
	nng_aio_set_msg(ctx->reqaio, msg);
	nng_ctx_send(ctx->reqctx, ctx->reqaio);
}

static object *
create_controller_params(controller *cp, object *auth)
{
	object *params;

	if (((params = alloc_obj()) == NULL) ||
	    (!add_obj_string(params, "controller", cp->name))) {
		free_obj(params);
		return (NULL);
	}
	if (!add_obj_obj(params, "auth", auth)) {
		free_obj(auth);
		free_obj(params);
		return (NULL);
	}
	return (params);
}

static void
do_status(nng_aio *aio, object *auth, const char *method, controller *cp)
{
	object *params;
	if (strcmp(method, "GET") != 0) {
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if ((params = create_controller_params(cp, auth)) == NULL) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}

	do_rpc(aio, cp, METHOD_GET_STATUS, params);
}

static void
do_networks(nng_aio *aio, object *auth, const char *method, controller *cp)
{
	object *params;
	if (strcmp(method, "GET") != 0) {
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if ((params = create_controller_params(cp, auth)) == NULL) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}

	do_rpc(aio, cp, METHOD_LIST_NETWORKS, params);
}

static void
do_get_network(nng_aio *aio, object *auth, controller *cp, uint64_t nwid)
{
	object *params;

	if (((params = create_controller_params(cp, auth)) == NULL) ||
	    (!add_obj_uint64(params, "network", nwid))) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	do_rpc(aio, cp, METHOD_GET_NETWORK, params);
}

static void
do_get_network_members(
    nng_aio *aio, object *auth, controller *cp, uint64_t nwid)
{
	object *params;

	if (((params = create_controller_params(cp, auth)) == NULL) ||
	    (!add_obj_uint64(params, "network", nwid))) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	do_rpc(aio, cp, METHOD_LIST_MEMBERS, params);
}

static void
do_get_member(
    nng_aio *aio, object *auth, controller *cp, uint64_t nwid, uint64_t nodeid)
{
	object *params;

	if (((params = create_controller_params(cp, auth)) == NULL) ||
	    (!add_obj_uint64(params, "network", nwid)) ||
	    (!add_obj_uint64(params, "member", nodeid))) {
		nng_aio_finish(aio, NNG_ENOMEM);
		free_obj(auth);
		return;
	}
	do_rpc(aio, cp, METHOD_GET_MEMBER, params);
}

static void
do_delete_member(
    nng_aio *aio, object *auth, controller *cp, uint64_t nwid, uint64_t nodeid)
{
	object *params;

	if (((params = create_controller_params(cp, auth)) == NULL) ||
	    (!add_obj_uint64(params, "network", nwid)) ||
	    (!add_obj_uint64(params, "member", nodeid))) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	do_rpc(aio, cp, METHOD_DELETE_MEMBER, params);
}

static void
do_authorize_member(
    nng_aio *aio, object *auth, controller *cp, uint64_t nwid, uint64_t nodeid)
{
	object *params;

	if (((params = create_controller_params(cp, auth)) == NULL) ||
	    (!add_obj_uint64(params, "network", nwid)) ||
	    (!add_obj_uint64(params, "member", nodeid))) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	do_rpc(aio, cp, METHOD_AUTH_MEMBER, params);
}

static void
do_deauthorize_member(
    nng_aio *aio, object *auth, controller *cp, uint64_t nwid, uint64_t nodeid)
{
	object *params;

	if (((params = create_controller_params(cp, auth)) == NULL) ||
	    (!add_obj_uint64(params, "network", nwid)) ||
	    (!add_obj_uint64(params, "member", nodeid))) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	do_rpc(aio, cp, METHOD_DEAUTH_MEMBER, params);
}

static void
do_network_member(nng_aio *aio, object *auth, const char *method,
    controller *cp, uint64_t nwid, uint64_t nodeid, const char *uri)
{
	if (strcmp(uri, "") == 0) {
		if (strcmp(method, "GET") == 0) {
			do_get_member(aio, auth, cp, nwid, nodeid);
			return;
		}
		if (strcmp(method, "DELETE") == 0) {
			do_delete_member(aio, auth, cp, nwid, nodeid);
			return;
		}
		// In the future we could support POST for creating
		// members. This is useful for ensuring that the member
		// exists.  Having said that, I believe that /authorize
		// or /deauthorize will create the member if it does
		// not already exist.
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if (strcmp(uri, "/authorize") == 0) {
		if (strcmp(method, "POST") == 0) {
			do_authorize_member(aio, auth, cp, nwid, nodeid);
			return;
		}
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if (strcmp(uri, "/deauthorize") == 0) {
		if (strcmp(method, "POST") == 0) {
			do_deauthorize_member(aio, auth, cp, nwid, nodeid);
			return;
		}
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	free_obj(auth);
	rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
}

static void
do_network(nng_aio *aio, object *auth, const char *method, controller *cp,
    uint64_t nwid, const char *uri)
{
	// The subcommand can be:
	//
	// ""  - GET, get network object, POST - create network
	//     -  (support delete?)
	// "/member" - GET, get the list of members
	// "/member/<node>" - GET, get the information for the member

	if (strcmp(uri, "") == 0) {
		if (strcmp(method, "GET") == 0) {
			do_get_network(aio, auth, cp, nwid);
			return;
		}
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if (strcmp(uri, "/member") == 0) {
		if (strcmp(method, "GET") == 0) {
			do_get_network_members(aio, auth, cp, nwid);
			return;
		}
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if (strncmp(uri, "/member/", strlen("/member/")) == 0) {
		uint64_t nodeid;
		char *   ep;

		uri += strlen("/member/");
		nodeid = strtoull(uri, &ep, 16);
		if ((ep != uri) && ((*ep == '\0') || (*ep == '/'))) {
			do_network_member(
			    aio, auth, method, cp, nwid, nodeid, ep);
			return;
		}
		free_obj(auth);
		rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
		return;
	}
	free_obj(auth);
	rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
}

static void
do_tokens(nng_aio *aio, object *auth, const char *method, controller *cp,
    object *body)
{
	object *params;
	object *a;
	char *  s;
	double  exp;

	if ((params = create_controller_params(cp, auth)) == NULL) {
		return;
	}
	if (strcmp(method, "GET") == 0) {
		do_rpc(aio, cp, METHOD_GET_TOKENS, params);
		return;
	}
	if (strcmp(method, "POST") != 0) {
		free_obj(params);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}

	if (body == NULL) {
		rpcerr(aio, NNG_HTTP_STATUS_BAD_REQUEST, "Bad JSON");
		return;
	}

	if (get_obj_obj(body, "roles", &a)) {
		object *roles;
		if (((roles = clone_obj(a)) == NULL) ||
		    (!add_obj_obj(params, "roles", roles))) {
			free_obj(params);
			free_obj(roles);
			nng_aio_finish(aio, NNG_ENOMEM);
			return;
		}
	}
	if ((get_obj_string(body, "desc", &s)) &&
	    (!add_obj_string(params, "desc", s))) {
		free_obj(params);
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	if ((get_obj_number(body, "expires", &exp)) &&
	    (!add_obj_number(params, "expires", exp))) {
		free_obj(params);
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}

	do_rpc(aio, cp, METHOD_CREATE_TOKEN, params);
}

static void
do_token(nng_aio *aio, object *auth, const char *method, controller *cp,
    const char *id)
{
	object *params;

	if ((params = create_controller_params(cp, auth)) == NULL) {
		return;
	}
	if (strcmp(method, "GET") == 0) {
		if (!add_obj_string(params, "token", id)) {
			free_obj(params);
			nng_aio_finish(aio, NNG_ENOMEM);
			return;
		}
		do_rpc(aio, cp, METHOD_GET_TOKEN, params);
		return;
	}
	if (strcmp(method, "DELETE") == 0) {
		if (!add_obj_string(params, "token", id)) {
			free_obj(params);
			nng_aio_finish(aio, NNG_ENOMEM);
			return;
		}
		do_rpc(aio, cp, METHOD_DELETE_TOKEN, params);
		return;
	}
	free_obj(params);
	rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
}

static void
do_self_password(nng_aio *aio, object *auth, const char *method,
    controller *cp, object *body)
{
	const char *id;
	char *      pass;
	object *    params;
	if ((params = create_controller_params(cp, auth)) == NULL) {
		return;
	}
	if (strcmp(method, "POST") != 0) {
		free_obj(params);
		rpcerr(aio, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}
	if (body == NULL) {
		rpcerr(aio, NNG_HTTP_STATUS_BAD_REQUEST, "Bad JSON");
		return;
	}
	if (!get_obj_string(body, "password", &pass)) {
		rpcerr(aio, NNG_HTTP_STATUS_BAD_REQUEST, "Password missing");
		return;
	}
	if (!add_obj_string(params, "password", pass)) {
		rpcerr(aio, NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return;
	}
	do_rpc(aio, cp, METHOD_SET_PASSWD, params);
}

#define PROXY_URI "/api/1.0/proxy"
#define PROXY_URI_LEN strlen(PROXY_URI)

char *
tokenize(char *s, char **np)
{
	char *n;
	while (isspace(*s)) {
		s++;
	}
	n = s;
	if (*s == '\0') {
		*np = n;
		return (NULL);
	}
	while ((!isspace(*n)) && (*n != '\0')) {
		n++;
	}
	if (isspace(*n)) {
		*n++ = '\0';
	}
	*np = n;
	return (s);
}

static bool
parse_auth(nng_http_req *req, object **op)
{
	object *    o;
	const char *h;
	char        buf[256];
	char *      mode;
	char *      cred;
	char *      next;

	if ((o = alloc_obj()) == NULL) {
		return (false);
	}

	// If an X-ZTC-OTP header is present, copy it.
	if ((h = nng_http_req_get_header(req, "X-ZTC-OTP")) != NULL) {
		if (!add_obj_string(o, "otp", h)) {
			free_obj(o);
			return (false);
		}
	}

	// We permit setting an X-ZTC-Token to pass credentials for tokens.
	// This allows to bypass the Bearer method, which is preferred.
	if ((h = nng_http_req_get_header(req, "X-ZTC-Token")) != NULL) {
		if (!add_obj_string(o, "token", h)) {
			free_obj(o);
			return (false);
		}
		*op = o;
		return (true);
	}

	if ((h = nng_http_req_get_header(req, "Authorization")) == NULL) {
		*op = o;
		return (true);
	}
	snprintf(buf, sizeof(buf), "%s", h);
	mode = tokenize(buf, &next);
	if (mode == 0) {
		*op = o;
		return (true);
	}

	// Bearer authentication
	if (strcmp(mode, "Bearer") == 0) {
		if ((cred = tokenize(next, &next)) == NULL) {
			// Create an invalid token.
			cred = "";
		}
		if (!add_obj_string(o, "token", cred)) {
			free_obj(o);
			return (false);
		}
		*op = o;
		return (true);
	}

	if (strcmp(mode, "Basic") == 0) {
		char   userpass[256];
		char * colon;
		size_t len;
		if ((cred = tokenize(next, &next)) == NULL) {
			*op = o;
			return (true);
		}
		if (mbedtls_base64_decode((void *) userpass, sizeof(userpass),
		        &len, (void *) cred, strlen(cred)) != 0) {
			// Indicative of bogus cred, pass empty.
			*op = o;
			return (true);
		}
		userpass[len] = '\0';
		if ((colon = strchr(userpass, ':')) == NULL) {
			// Invalid auth header.
			*op = o;
			return (true);
		}
		*colon++ = '\0';
		if ((!add_obj_string(o, "user", userpass)) ||
		    (!add_obj_string(o, "pass", colon))) {
			free_obj(o);
			return (false);
		}
		*op = o;
		return (true);
	}

	// Other auth headers, just pass empty auth object.
	*op = o;
	return (true);
}

static void
proxy_api(nng_aio *aio)
{
	nng_http_req *req;
	const char *  uri;
	const char *  method;
	const char *  name;
	char *        ep;
	controller *  cp;
	object *      auth;

	// Our API is:
	// GET /api/1.0/proxy/<name>/status
	// GET /api/1.0/proxy/<name>/network
	// GET /api/1.0/proxy/<name>/network/<nwid>/member
	// GET /api/1.0/proxy/<name>/network/<nwid>/member/<node>
	// DELETE /api/1.0/proxy/<name>/network/<nwid>/member/<node>
	// POST
	// /api/1.0/proxy/<name>/network/<nwid>/member/<node>/authorize
	// POST
	// /api/1.0/proxy/<name>/network/<nwid>/member/<node>/deauthorize
	// POST /api/1.0/proxy/<name>/token
	// DELETE /api/1.0/proxy/<name>/token/<tokenid>

	req    = nng_aio_get_input(aio, 0);
	method = nng_http_req_get_method(req);
	uri    = nng_http_req_get_uri(req);

	if ((strncmp(uri, PROXY_URI, PROXY_URI_LEN) != 0) ||
	    (uri[PROXY_URI_LEN] != '/')) {
		// This is not us.
		rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
		return;
	}
	uri += PROXY_URI_LEN + 1;
	name = uri;
	while ((*uri != '/') && (*uri != '\0')) {
		uri++;
	}
	for (cp = controllers; cp != NULL; cp = cp->next) {
		if ((memcmp(name, cp->name, strlen(cp->name)) == 0) &&
		    ((*uri == '/') || (*uri == '\0'))) {
			break;
		}
	}
	if (cp == NULL) {
		rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
		return;
	}

	if (!parse_auth(req, &auth)) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}

	// Make it simpler for now.  The server framework will filter
	// responses as neccessary.
	if (strcmp(method, "HEAD") == 0) {
		method = "GET";
	}

	// For now we are very picky, and do not support a trailing
	// "/".
	if (strcmp(uri, "/status") == 0) {
		do_status(aio, auth, method, cp);
		return;
	}
	if (strcmp(uri, "/network") == 0) {
		do_networks(aio, auth, method, cp);
		return;
	}
	if (strncmp(uri, "/network/", strlen("/network/")) == 0) {
		uint64_t nwid;

		uri += strlen("/network/");
		nwid = strtoull(uri, &ep, 16);
		if ((*ep == '/') || (*ep == '\0')) {
			do_network(aio, auth, method, cp, nwid, ep);
			return;
		}
		rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
		return;
	}
	if (strcmp(uri, "/token") == 0) {
		char *  data;
		size_t  len;
		object *body;

		nng_http_req_get_data(req, (void **) &data, &len);
		body = parse_obj(data, len);

		do_tokens(aio, auth, method, cp, body);
		free_obj(body);
		return;
	}
	if (strncmp(uri, "/token/", strlen("/token/")) == 0) {
		uri += strlen("/token/");
		ep = (char *) uri;
		while ((*ep != '/') && (*ep != '\0')) {
			ep++;
		}
		// Tokens don't have a subpath for now.
		if ((*ep != '\0') || (ep == uri)) {
			rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
			return;
		}
		do_token(aio, auth, method, cp, uri);
		return;
	}
	if (strcmp(uri, "/password") == 0) {
		char *  data;
		size_t  len;
		object *body;
		nng_http_req_get_data(req, (void **) &data, &len);
		body = parse_obj(data, len);

		do_self_password(aio, auth, method, cp, body);
		free_obj(body);
		return;
	}
	rpcerr(aio, NNG_HTTP_STATUS_NOT_FOUND, NULL);
}

void
serve_http(void)
{
	nng_url *         url;
	nng_http_server * server;
	nng_http_handler *h;
	int               rv;

	// Allocate and hold the server.
	if (((rv = nng_url_parse(&url, httpurl)) != 0) ||
	    ((rv = nng_http_server_hold(&server, url)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	// Directory handler.  Note that index.html is served for directories
	// automatically. (Q: Should this be optional?)
	if (((rv = nng_http_handler_alloc_directory(
	          &h, static_uri, static_dir)) != 0) ||
	    ((rv = nng_http_server_add_handler(server, h)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	// API handler.
	// Note that we set the method to NULL, as we want to receive
	// all methods, not just GET.  This means we are obliged to
	// inspect the method.  We only accept up to 200K, because
	// there is no reason to ever receive a larger object than that.
	if (((rv = nng_http_handler_alloc(&h, PROXY_URI, proxy_api)) != 0) ||
	    ((rv = nng_http_handler_collect_body(h, true, 204800)) != 0) ||
	    ((rv = nng_http_handler_set_method(h, NULL)) != 0) ||
	    ((rv = nng_http_handler_set_tree(h)) != 0) ||
	    ((rv = nng_http_server_add_handler(server, h)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	// TLS configuration (optional).
	if (strncmp(httpurl, "https", 5) == 0) {
		if (tls == NULL) {
			fprintf(stderr, "Missing TLS configuration\n");
			exit(1);
		}
		if ((rv = nng_http_server_set_tls(server, tls)) != 0) {
			fprintf(stderr, "TLS: %s\n", nng_strerror(rv));
			exit(1);
		}
	}

	if ((rv = nng_http_server_start(server)) != 0) {
		fprintf(stderr, "HTTP Start: %s\n", nng_strerror(rv));
		exit(1);
	}

	printf("HTTP listening at %s\n", httpurl);
}

static void
load_config(const char *path)
{
	object *cfg;
	object *proxy;
	object *tobj;

	// The configuration will leak, but we only ever exit
	// abnormally.
	if ((cfg = cfgfile_load(path)) == NULL) {
		exit(1);
	}

	// Locate the definition for both our controller, and the
	// proxy.
	if ((!get_obj_obj(cfg, "proxy", &proxy)) ||
	    (!get_obj_string(proxy, "survey", &survurl)) ||
	    (!get_obj_string(proxy, "http", &httpurl))) {
		fprintf(stderr, "proxy configuration invalid\n");
		exit(1);
	}

	// Locate the definition for web server.
	// This is now mandatory, but it could be optional.
	if ((!get_obj_obj(cfg, "static", &tobj)) ||
	    (!get_obj_string(tobj, "uri", &static_uri)) ||
	    (!get_obj_string(tobj, "dir", &static_dir))) {
		fprintf(stderr, "static pages configuration invalid\n");
		exit(1);
	}

	// TLS can be missing.
	if (get_obj_obj(cfg, "tls", &tobj)) {
		int               rv;
		char *            key;
		char *            str;
		bool              cauth;
		nng_tls_auth_mode amode;

		if ((rv = nng_tls_config_alloc(&tls, NNG_TLS_MODE_SERVER)) !=
		    0) {
			fprintf(stderr, "%s\n", nng_strerror(rv));
			exit(1);
		}
		str = NULL;
		get_obj_string(tobj, "keypass", &str);
		if ((get_obj_string(tobj, "keyfile", &key)) &&
		    ((rv = nng_tls_config_cert_key_file(tls, key, str)) !=
		        0)) {
			fprintf(stderr, "TLS keyfile: %s\n", nng_strerror(rv));
			exit(1);
		}
		if (get_obj_string(tobj, "server", &str) &&
		    ((rv = nng_tls_config_server_name(tls, str)) != 0)) {
			fprintf(stderr, "TLS server: %s\n", nng_strerror(rv));
			exit(1);
		}
		if (get_obj_string(tobj, "cacert", &str) &&
		    ((rv = nng_tls_config_ca_file(tls, str)) != 0)) {
			fprintf(stderr, "TLS cacert: %s\n", nng_strerror(rv));
			exit(1);
		}
		cauth = false;
		amode = NNG_TLS_AUTH_MODE_NONE;
		if (get_obj_bool(tobj, "clientauth", &cauth) && cauth) {
			amode = NNG_TLS_AUTH_MODE_REQUIRED;
		}
		if ((rv = nng_tls_config_auth_mode(tls, amode)) != 0) {
			fprintf(stderr, "%s\n", nng_strerror(rv));
			exit(1);
		}
	}

	// This can be missing, but if it is, then we are an ephemeral
	// proxy server.  This is generally not desirable.
	(void) get_obj_string(cfg, "zthome", &zthome);
}

int
main(int argc, char **argv)
{
	int         optc;
	char *      opta;
	int         opti = 1;
	const char *path = CONFIG;
	int         rv;
	uint32_t    seed;

	srand(time(NULL));
	atomic_store(&req_id, rand());

	ctxinit();

	if (((rv = nng_mtx_alloc(&lock)) != 0) ||
	    ((rv = nng_mtx_alloc(&survlk)) != 0) ||
	    ((rv = nng_cv_alloc(&survcv, survlk)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	while (nng_opts_parse(argc, argv, opts, &optc, &opta, &opti) == 0) {
		switch (optc) {
		case 'c':
			path = opta;
			break;
		}
	}

	if ((rv = nng_zt_register()) != 0) {
		fprintf(stderr, "Failed to register ZT transport: %s\n",
		    nng_strerror(rv));
	}

	load_config(path);

	serve_http();

	survey_loop();

	ctxfini();
}
