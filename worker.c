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

// worker
//
// The worker registers an NNG listener on at a predefined ZeroTier
// address, which acts as a REP server, where it receives requests.
// These requests are forwarded to an HTTP REST server (the local
// controller) - usually running on localhost port 9993.
//
// The worker *also* attempts to set up a responder socket using
// an outgoing dialer to the proxy.  This proxy provides the ZeroTier
// local network address, where proxy can reach us.  This is a TCP
// address.

#include "config.h"

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>
#include <nng/transport/zerotier/zerotier.h>

#include "auth.h"
#include "cfgfile.h"
#include "object.h"
#include "util.h"
#include "worker.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef CONFIG
#define CONFIG "worker.cfg"
#endif

nng_socket repsock;
nng_socket survsock;
char *     zthome;
int        debug;
char *     userdb;
char *     tokendb;

typedef enum {
	STATE_RECVING,
	STATE_HTTPING,
	STATE_REPLYING,
} worker_state;

typedef struct proxy   proxy;
typedef struct netperm netperm;

nng_tls_config *tls = NULL;

struct worker {
	nng_ctx          ctx; // REP context
	nng_http_req *   req;
	nng_http_res *   res;
	nng_aio *        aio;
	worker_state     state;
	nng_http_client *client;
	uint64_t         id; // request ID of pending request
	worker_http_cb   http_cb;
};

struct controller {
	char *           addr;
	char *           name;
	char *           secret;
	char *           host; // for HTTP
	nng_http_client *client;
	worker_ops *     ops;
};

struct proxy {
	char *       survurl;
	char *       repurl;
	nng_sockaddr repsa;
	nng_dialer   d; // outgoing dialer to surveyor
	nng_listener l; // incoming listener from req
};

struct netperm {
	uint64_t nwid;
	bool     allow;
	netperm *next;
};

worker *workers  = NULL;
int     nworkers = 4; // some kind of default

controller *controllers;
int         ncontrollers;

proxy *proxies;
int    nproxies;

netperm *netperms;

// Note that the CTRLR NODE will almost certainly not be the same as the ZT
// address.  That's because we can create per-process (ephemeral) ZT nodes
// for the worker, unrelated to the controller.  In fact the controller and
// the worker need not have any ZT networks in common!

bool
nwid_allowed(uint64_t nwid)
{
	netperm *np;

	// Empty permissions means all allowed.
	if (netperms == NULL) {
		return (true);
	}
	for (np = netperms; np != NULL; np++) {
		if ((nwid == np->nwid) || (np->nwid == 0)) {
			return (np->allow);
		}
	}

	// But if not present in a fixed list, then default is deny.
	return (false);
}

static void
survey_loop(void)
{
	for (;;) {
		nng_msg *    msg;
		nng_pipe     pipe;
		int          rv;
		uint32_t     port;
		nng_sockaddr raddr;
		nng_sockaddr laddr;
		object *     obj;
		object *     arr;
		char *       body;

		switch ((rv = nng_recvmsg(survsock, &msg, 0))) {
		case 0:
			break;
		case NNG_ECLOSED:
			return;
		default:
			fprintf(stderr, "Survey recv: %s\n", nng_strerror(rv));
			continue;
		}
		pipe = nng_msg_get_pipe(msg);

		if (debug > 1) {
			nng_pipe_getopt_sockaddr(
			    pipe, NNG_OPT_REMADDR, &raddr);
			nng_pipe_getopt_sockaddr(
			    pipe, NNG_OPT_LOCADDR, &laddr);
			printf("Survey-Recv {\n");
			printf("\tfrom: zt://%llx.%llx:%u\n",
			    raddr.s_zt.sa_nodeid, raddr.s_zt.sa_nwid,
			    raddr.s_zt.sa_port);
			printf("\tto:   zt://%llx.%llx:%u\n",
			    laddr.s_zt.sa_nodeid, laddr.s_zt.sa_nwid,
			    laddr.s_zt.sa_port);
			printf("}\n");
		} else if (debug > 0) {
			putc('s', stdout);
			fflush(stdout);
		}

		port = 0;
		for (int i = 0; i < nproxies; i++) {
			proxy *p = &proxies[i];
			if (nng_dialer_id(nng_pipe_dialer(pipe)) ==
			    nng_dialer_id(p->d)) {
				port = p->repsa.s_zt.sa_port;
				break;
			}
		}
		if (port == 0) {
			fprintf(stderr, "Survey recv: bad dialer?\n");
			continue;
		}

		arr = alloc_arr();
		obj = alloc_obj();
		if (((arr == NULL) || (obj == NULL)) ||
		    (!add_obj_int(obj, "port", port))) {
			free_obj(arr);
			free_obj(obj);
			nng_msg_free(msg);
			fprintf(stderr, "Out of memory\n");
			continue;
		}
		for (int i = 0; i < ncontrollers; i++) {
			struct controller *cp = &controllers[i];
			// If this fails, we will get a short response,
			// but carry on.
			add_arr_string(arr, cp->name);
		}
		if (!add_obj_obj(obj, "controllers", arr)) {
			free_obj(arr);
			free_obj(obj);
			nng_msg_free(msg);
			fprintf(stderr, "Out of memory\n");
			continue;
		}

		body = print_obj(obj);
		free_obj(obj);

		nng_msg_clear(msg);
		if (body == NULL) {
			fprintf(stderr, "Out of memory\n");
			nng_msg_free(msg);
			continue;
		}

		if (nng_msg_append(msg, body, strlen(body)) != 0) {
			free(body);
			nng_msg_free(msg);
			fprintf(stderr, "Out of memory\n");
			continue;
		}

		if (debug > 1) {
			printf("Survey-Send: %s\n", body);
			printf("\tfrom: zt://%llx.%llx:%u\n",
			    laddr.s_zt.sa_nodeid, laddr.s_zt.sa_nwid,
			    laddr.s_zt.sa_port);
			printf("\tto:   zt://%llx.%llx:%u\n",
			    raddr.s_zt.sa_nodeid, raddr.s_zt.sa_nwid,
			    raddr.s_zt.sa_port);
		} else if (debug > 0) {
			putc('S', stdout);
			fflush(stdout);
		}
		free(body);
		switch (nng_sendmsg(survsock, msg, 0)) {
		case 0:
			break;
		case NNG_ECLOSED:
			nng_msg_free(msg);
			return;
		default:
			nng_msg_free(msg);
			break;
		}
	}
}

// now returns the current time of day since the UNIX epoch in millseconds.
// As we only use this for token expiration, we have time granularity of
// 1 second.  That's fine for us.
static uint64_t
now(void)
{
	uint64_t ms;
	ms = time(NULL);
	ms *= 1000; // convert to milliseconds
	return (ms);
}

static void
recv_request(worker *w)
{
	w->state = STATE_RECVING;
	nng_ctx_recv(w->ctx, w->aio);
}

static void
send_resp(worker *w, const char *key, object *obj)
{
	nng_msg *msg = NULL;
	object * res = NULL;
	char *   str;
	char     idbuf[32];

	snprintf(idbuf, sizeof(idbuf), "%llx", w->id);

	if ((nng_msg_alloc(&msg, 0) != 0) || ((res = alloc_obj()) == NULL) ||
	    (!add_obj_string(res, "jsonrpc", "2.0")) ||
	    (!add_obj_string(res, "id", idbuf)) ||
	    (!add_obj_obj(res, key, obj))) {
		free_obj(res);
		free_obj(obj);
		nng_msg_free(msg);
		recv_request(w);
		return;
	}

	str = print_obj(res);
	free_obj(res);

	if ((str == NULL) || (nng_msg_append(msg, str, strlen(str)) != 0)) {
		nng_msg_free(msg);
		free(res);
		recv_request(w);
		return;
	}

	w->state = STATE_REPLYING;
	nng_aio_set_msg(w->aio, msg);
	nng_ctx_send(w->ctx, w->aio);
	return;
}

void
send_err(worker *w, int code, const char *rsn)
{
	object * err = NULL;
	nng_msg *msg = NULL;
	char *   str = NULL;

	if (rsn == NULL) {
		switch (code) {
		case E_NOMEM:
			rsn = "Out of memory";
			break;
		case E_INTERNAL:
			rsn = "Internal error";
			break;
		case E_NOCTRLR:
			rsn = "No such controller";
			break;
		case E_BADJSON:
			rsn = "Bad JSON from backend";
			break;
		case E_BADMETHOD:
			rsn = "Method not found";
			break;
		default:
			rsn = "Unknown error";
			break;
		}
	}
	if (((err = alloc_obj()) == NULL) ||
	    (!add_obj_int(err, "code", code)) ||
	    (!add_obj_string(err, "message", rsn))) {
		free_obj(err);
		recv_request(w);
		return;
	}
	send_resp(w, "error", err);
}

void
send_result(worker *w, object *o)
{
	send_resp(w, "result", o);
}

static void get_status(worker *, object *);
static void get_networks(worker *, object *);
static void get_network(worker *, object *);
static void get_network_members(worker *, object *);
static void get_network_member(worker *, object *);
static void delete_network_member(worker *, object *);
static void authorize_network_member(worker *, object *);
static void deauthorize_network_member(worker *, object *);

static struct {
	const char *method;
	void (*func)(worker *, object *);
	uint64_t rolemask;
} jsonrpc_methods[] = {
	{ "get-status", get_status, 0 },
	{ "get-networks", get_networks, 0 },
	{ "get-network", get_network, 0 },
	{ "get-network-members", get_network_members, 0 },
	{ "get-network-member", get_network_member, 0 },
	{ "delete-network-member", delete_network_member, 0 },
	{ "authorize-network-member", authorize_network_member, 0 },
	{ "deauthorize-network-member", deauthorize_network_member, 0 },
	{ NULL, NULL, 0 },
};

static void
jsonrpc(worker *w, object *reqobj, const char *meth, object *parm)
{
	for (int i = 0; jsonrpc_methods[i].method != NULL; i++) {
		if (strcmp(jsonrpc_methods[i].method, meth) == 0) {
			jsonrpc_methods[i].func(w, parm);
			free_obj(reqobj);
			return;
		}
	}
	free_obj(reqobj);
	send_err(w, E_BADMETHOD, NULL);
}

nng_http_req *
worker_http_req(worker *w)
{
	return (w->req);
}

nng_http_res *
worker_http_res(worker *w)
{
	return (w->res);
}

void
worker_http(worker *w, worker_http_cb cb)
{
	int rv;
	w->http_cb = cb;
	w->state   = STATE_HTTPING;

	if (debug > 1) {
		void * body;
		size_t len;
		nng_http_req_get_data(w->req, &body, &len);
		printf("Controller-Send %s %s:\n",
		    nng_http_req_get_method(w->req),
		    nng_http_req_get_uri(w->req));
		fwrite(body, len, 1, stdout);
		printf("\n");
	}

	nng_http_client_transact(w->client, w->req, w->res, w->aio);
}

// better than strcmp because it is NULL safe, and uses more natural booleans.
// (returns false if either is NULL, or strcmp != 0).
bool
samestr(const char *s1, const char *s2)
{
	if ((s1 == NULL) || (s2 == NULL) || (strcmp(s1, s2) != 0)) {
		return (false);
	}
	return (true);
}

static controller *
find_controller(worker *w, const char *name)
{
	for (int i = 0; i < ncontrollers; i++) {
		if (strcmp(controllers[i].name, name) == 0) {
			w->client = controllers[i].client;
			return (&controllers[i]);
		}
	}
	return (NULL);
}

static bool
valid_name(const char *name)
{
	char c;

	// Insist that the name start with a letter or an underscore.
	if ((name == NULL) || ((!isalpha(*name)) && (*name != '_'))) {
		return (false);
	}
	while ((c = *name) != '\0') {
		name++;
		if ((!isalnum(c)) && (c != '_') && (c != '-')) {
			return (false);
		}
	}
	return (true);
}

const char *
get_controller_secret(controller *cp)
{
	return (cp->secret);
}

const char *
get_controller_host(controller *cp)
{
	return (cp->host);
}

static bool
get_auth_param(worker *w, object *params, char **userp, uint64_t *rolesp)
{
	char *  id;
	char *  pass;
	char *  otp;
	object *obj;
	user *  user;
	int     code;

	// Rules:
	// We accept a token, if one is present.
	// Otherwise, we check for user, password, and otp. If the
	// otp is not present, but is required, we will fail with
	// an error condition requesting it.

	if (!get_obj_obj(params, "auth", &obj)) {
		send_err(w, E_AUTHFAIL, NULL);
		return (false);
	}

	if (get_obj_string(obj, "token", &id)) {
		token *tok;
		if ((tok = find_token(id)) == NULL) {
			send_err(w, E_AUTHFAIL, NULL); // Invalid token.
			return (false);
		}
		if ((userp != NULL) &&
		    ((*userp = strdup(user_name(token_user(tok)))) == NULL)) {
			free_token(tok);
			send_err(w, E_NOMEM, NULL);
			return (false);
		}

		if (rolesp != NULL) {
			*rolesp = (uint64_t) token_roles(tok);
		}
		free_token(tok);
		return (true);
	}

	otp = NULL;
	if ((!get_obj_string(obj, "user", &id)) ||
	    (!get_obj_string(obj, "pass", &pass))) {
		send_err(w, E_AUTHFAIL, NULL);
		return (false);
	}
	get_obj_string(obj, "otp", &otp);
	if ((user = auth_user(id, pass, otp, &code)) == NULL) {
		send_err(w, code, NULL);
		return (false);
	}

	// If the token has an expire field, check it.
	if ((userp != NULL) && ((*userp = strdup(user_name(user))) == NULL)) {
		free_user(user);
		send_err(w, E_NOMEM, NULL);
		return (false);
	}

	if (rolesp != NULL) {
		*rolesp = (uint64_t) user_roles(user);
	}
	free_user(user);
	return (true);
}

static bool
get_controller_param(worker *w, object *params, controller **cpp)
{
	char *      name;
	controller *cp;

	if (!get_obj_string(params, "controller", &name)) {
		send_err(w, E_BADPARAMS, "controller parameter required");
		return (false);
	}
	if ((cp = find_controller(w, name)) == NULL) {
		send_err(w, E_NOCTRLR, NULL);
		return (false);
	}

	*cpp = cp;
	return (true);
}

static void
get_status(worker *w, object *params)
{
	controller *cp;

	if (get_controller_param(w, params, &cp)) {
		cp->ops->get_status(cp, w);
	}
}

static void
get_networks(worker *w, object *params)
{
	controller *cp;

	if (get_controller_param(w, params, &cp)) {
		cp->ops->get_networks(cp, w);
	}
}

static bool
get_network_param(worker *w, object *params, controller **cpp, uint64_t *nwidp)
{
	controller *cp;
	uint64_t    nwid;

	if (!get_controller_param(w, params, &cp)) {
		return (false);
	}
	if (!get_obj_uint64(params, "network", &nwid)) {
		send_err(w, E_BADPARAMS, "network parameter required");
		return (false);
	}
	if (!nwid_allowed(nwid)) {
		// Security: Treat network denied as if it does not exist.
		send_err(w, 404, "no such network");
		return (false);
	}

	*cpp   = cp;
	*nwidp = nwid;
	return (true);
}

static void
get_network(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_network_param(w, params, &cp, &nwid)) {
		cp->ops->get_network(cp, w, nwid);
	}
}

static void
get_network_members(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_network_param(w, params, &cp, &nwid)) {
		cp->ops->get_members(cp, w, nwid);
	}
}

static bool
get_member_param(worker *w, object *params, controller **cpp, uint64_t *nwidp,
    uint64_t *memidp)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    memid;

	if (!get_network_param(w, params, &cp, &nwid)) {
		return (false);
	}
	if (!get_obj_uint64(params, "member", &memid)) {
		send_err(w, E_BADPARAMS, "member parameter required");
		return (false);
	}
	*cpp    = cp;
	*nwidp  = nwid;
	*memidp = memid;
	return (true);
}

static void
get_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_member_param(w, params, &cp, &nwid, &member)) {
		cp->ops->get_member(cp, w, nwid, member);
	}
}

static void
delete_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param(w, params, NULL, NULL) &&
	    get_member_param(w, params, &cp, &nwid, &member)) {
		cp->ops->delete_member(cp, w, nwid, member);
	}
}

static void
authorize_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_member_param(w, params, &cp, &nwid, &member)) {
		cp->ops->authorize_member(cp, w, nwid, member);
	}
}

static void
deauthorize_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_member_param(w, params, &cp, &nwid, &member)) {
		cp->ops->deauthorize_member(cp, w, nwid, member);
	}
}

static void
recv_cb(worker *w)
{
	int      rv;
	object * obj;
	object * parm;
	char *   meth;
	char *   body;
	nng_msg *msg;
	char *   vers;

	// We are waiting for an incoming request.
	if ((rv = nng_aio_result(w->aio)) != 0) {
		if (rv == NNG_ECLOSED) {
			return;
		}
		recv_request(w);
		return;
	}

	msg = nng_aio_get_msg(w->aio);
	nng_aio_set_msg(w->aio, NULL);
	nng_http_req_reset(w->req);
	nng_http_res_reset(w->res);
	w->id = 0;

	if (debug > 1) {
		nng_sockaddr raddr;
		nng_sockaddr laddr;
		nng_pipe     pipe = nng_msg_get_pipe(msg);
		nng_pipe_getopt_sockaddr(pipe, NNG_OPT_REMADDR, &raddr);
		nng_pipe_getopt_sockaddr(pipe, NNG_OPT_LOCADDR, &laddr);
		printf("Rep-Recv {\n");
		printf("\tfrom: zt://%llx.%llx:%u\n", raddr.s_zt.sa_nodeid,
		    raddr.s_zt.sa_nwid, raddr.s_zt.sa_port);
		printf("\tto:   zt://%llx.%llx:%u\n", laddr.s_zt.sa_nodeid,
		    laddr.s_zt.sa_nwid, laddr.s_zt.sa_port);
		printf("}\n");
	} else if (debug > 0) {
		putc('r', stdout);
		fflush(stdout);
	}

	obj = parse_obj(nng_msg_body(msg), nng_msg_len(msg));
	nng_msg_free(msg);

	// The following is sort of a violation of the JSON-RPC 2.0
	// specification, but given that we control both sides of this
	// a more constrained approach is reasonable.
	//
	// We reject batch calls, and we insist that a valid numeric ID
	// be present (which must be non-zero 32-bits).  We also insist
	// that The method and parameters be present, and the latter be
	// an object.
	//
	// If the request is malformed we send a -32600.  This won't
	// have the request ID associated with it, so technically we
	// are out of spec, but the original request object is already
	// malformed, and as we said -- we control both sides.  It's
	// not worth the extra trouble to conform to a useless part of
	// the spec that will never occur.

	if ((obj == NULL) || (!get_obj_string(obj, "jsonrpc", &vers)) ||
	    (strcmp(vers, "2.0") != 0) ||
	    (!get_obj_uint64(obj, "id", &w->id)) ||
	    (!get_obj_string(obj, "method", &meth)) ||
	    (!get_obj_obj(obj, "params", &parm))) {
		send_err(w, E_BADREQUEST, "Invalid request object");
		free_obj(obj);
		return;
	}

	jsonrpc(w, obj, meth, parm);
	return;
}

static void
http_cb(worker *w)
{
	nng_aio *      aio = w->aio;
	nng_http_res * res = w->res;
	int            rv;
	void *         body;
	size_t         len;
	worker_http_cb cb;

	if ((cb = w->http_cb) == NULL) {
		send_err(w, E_INTERNAL, "Missing HTTP callback");
		return;
	}
	w->http_cb = NULL;

	if ((rv = nng_aio_result(aio)) != 0) {
		send_err(w, E_INTERNAL, nng_strerror(rv));
		return;
	}

	nng_http_res_get_data(res, &body, &len);
	if ((rv = nng_http_res_get_status(res)) > 299) {
		if (debug > 1) {
			printf("Controller-Error: %d %s\n", rv,
			    nng_http_res_get_reason(res));
			fwrite(body, len, 1, stdout);
			printf("\n");
		}
		send_err(w, rv, nng_http_res_get_reason(res));
		return;
	}

	if (debug > 1) {
		printf("Controller-Reply:\n");
		fwrite(body, len, 1, stdout);
		printf("\n");
	}
	cb(w, body, len);
	return;
}

static void
reply_cb(worker *w)
{
	nng_aio *aio = w->aio;
	int      rv;

	if ((rv = nng_aio_result(aio)) != 0) {
		nng_msg_free(nng_aio_get_msg(aio));
		nng_aio_set_msg(aio, NULL);
		if (rv == NNG_ECLOSED) {
			return;
		}
	}
	recv_request(w);
}

static void
worker_cb(void *arg)
{
	worker *w = arg;

	switch (w->state) {
	case STATE_RECVING:
		recv_cb(w);
		break;

	case STATE_HTTPING:
		http_cb(w);
		break;

	case STATE_REPLYING:
		reply_cb(w);
		break;
	}
}

static void
start_workers(void)
{
	if ((workers = calloc(nworkers, sizeof(worker))) == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	if (debug > 0) {
		printf("Using %d workers\n", nworkers);
	}

	for (int i = 0; i < nworkers; i++) {
		worker *w = &workers[i];
		int     rv;

		if (((rv = nng_aio_alloc(&w->aio, worker_cb, w)) != 0) ||
		    ((rv = nng_http_req_alloc(&w->req, NULL)) != 0) ||
		    ((rv = nng_http_res_alloc(&w->res)) != 0) ||
		    ((rv = nng_ctx_open(&w->ctx, repsock)) != 0)) {
			fprintf(stderr, "%s\n", nng_strerror(rv));
			exit(1);
		}
		recv_request(w);
	}
}

static void
setup_controllers(void)
{
	for (int i = 0; i < ncontrollers; i++) {
		int         rv;
		nng_url *   url;
		controller *cp = &controllers[i];

		// Allocate an HTTP client.  We can reuse the client.
		if (((rv = nng_url_parse(&url, cp->addr)) != 0) ||
		    ((rv = nng_http_client_alloc(&cp->client, url)) != 0)) {
			fprintf(stderr, "%s\n", nng_strerror(rv));
			exit(1);
		}

		if (((strcmp(url->u_scheme, "http") == 0) &&
		        (strcmp(url->u_port, "80") == 0)) ||
		    ((strcmp(url->u_scheme, "https") == 0) &&
		        (strcmp(url->u_port, "443") == 0))) {
			cp->host = strdup(url->u_host);
		} else {
			cp->host = strdup(url->u_hostname);
		}
		if (cp->host == NULL) {
			fprintf(stderr, "Out of memory\n");
			exit(1);
		}
		nng_url_free(url);

		if (strncmp(cp->addr, "https", 5) == 0) {
			if (tls == NULL) {
				fprintf(stderr, "Missing TLS configuration\n");
				exit(1);
			}
			if ((rv = nng_http_client_set_tls(cp->client, tls)) !=
			    0) {
				fprintf(stderr, "TLS: %s\n", nng_strerror(rv));
				exit(1);
			}
		}
	}
}

static void
setup_sockets(void)
{
	int   rv;
	char *zth;
	if (((rv = nng_rep0_open(&repsock)) != 0) ||
	    ((rv = nng_respondent0_open(&survsock)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}
	if ((zth = zthome) == NULL) {
		return;
	}
	if (((rv = nng_setopt_string(repsock, NNG_OPT_ZT_HOME, zth)) != 0) ||
	    ((rv = nng_setopt_string(survsock, NNG_OPT_ZT_HOME, zth)) != 0) ||
	    ((rv = nng_setopt_ms(survsock, NNG_OPT_ZT_PING_TIME, 1000)) !=
	        0) ||
	    ((rv = nng_setopt_ms(survsock, NNG_OPT_ZT_CONN_TIME, 1000)) !=
	        0) ||
	    ((rv = nng_setopt_ms(survsock, NNG_OPT_RECONNMINT, 1)) != 0) ||
	    ((rv = nng_setopt_ms(survsock, NNG_OPT_RECONNMAXT, 10)) != 0)) {
		fprintf(stderr, "setting options: %s\n", nng_strerror(rv));
		exit(1);
	}
}

static void
setup_proxy(proxy *p)
{
	char *s;
	int   rv;

	if (((rv = nng_listener_create(&p->l, repsock, p->repurl)) != 0) ||
	    ((rv = nng_listener_start(p->l, 0)) != 0) ||
	    ((rv = nng_listener_getopt_sockaddr(
	          p->l, NNG_OPT_LOCADDR, &p->repsa)) != 0) ||
	    ((rv = nng_listener_getopt_string(p->l, NNG_OPT_URL, &s)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}
	printf("REP listening at %s\n", s);

	// We dial in the background.
	if (((rv = nng_dialer_create(&p->d, survsock, p->survurl)) != 0) ||

	    ((rv = nng_dialer_start(p->d, NNG_FLAG_NONBLOCK)) != 0)) {
		fprintf(stderr, "%s\n", nng_strerror(rv));
		exit(1);
	}

	printf("RESPONDENT dialing to %s\n", p->survurl);
}

static void
setup_proxies(void)
{
	setup_sockets();
	for (int i = 0; i < nproxies; i++) {
		setup_proxy(&proxies[i]);
	}
}

static void
load_config(const char *path)
{
	object *cfg;
	object *obj;
	object *arr;

	// The configuration will leak, but we only ever exit
	// abnormally.
	if ((cfg = cfgfile_load(path)) == NULL) {
		exit(1);
	}

	if ((!get_obj_obj(cfg, "proxies", &arr)) || (!is_obj_array(arr))) {
		fprintf(stderr, "cannot locate proxies array\n");
		exit(1);
	}
	nproxies = get_arr_len(arr);
	if ((proxies = calloc(sizeof(proxy), nproxies)) == NULL) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		exit(1);
	}

	for (int i = 0; i < nproxies; i++) {
		proxy *pp = &proxies[i];

		if ((!get_arr_obj(arr, i, &obj)) ||
		    (!get_obj_string(obj, "survey", &pp->survurl)) ||
		    (!get_obj_string(obj, "reqrep", &pp->repurl))) {
			fprintf(stderr, "proxy %d malformed\n", i);
			exit(1);
		}
	}

	// Look up the list of controllers.
	if ((!get_obj_obj(cfg, "controllers", &arr)) || (!is_obj_array(arr))) {
		fprintf(stderr, "cannot locate controllers array\n");
		exit(1);
	}
	ncontrollers = get_arr_len(arr);
	if ((controllers = calloc(sizeof(controller), ncontrollers)) == NULL) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		exit(1);
	}

	for (int i = 0; i < ncontrollers; i++) {
		controller *cp = &controllers[i];
		char *      ct;

		if ((!get_arr_obj(arr, i, &obj)) ||
		    (!get_obj_string(obj, "address", &cp->addr)) ||
		    (!get_obj_string(obj, "secret", &cp->secret)) ||
		    (!get_obj_string(obj, "name", &cp->name))) {
			fprintf(stderr, "controller %d incomplete\n", i);
			exit(1);
		}
		if (!get_obj_string(obj, "type", &ct)) {
			// Fall back to default "controller"
			ct = "controller";
		}

		if (strcmp(ct, "controller") == 0) {
			cp->ops = &controller_ops;
		} else if (strcmp(ct, "central") == 0) {
			cp->ops = &central_ops;
		} else {
			fprintf(stderr, "unknown controller type %s\n", ct);
			exit(1);
		}

		if (!valid_name(cp->name)) {
			fprintf(stderr, "bad name for controller %d: %s\n", i,
			    cp->name);
			exit(1);
		}

		for (int j = 0; j < i; j++) {
			if (strcmp(cp->name, controllers[j].name) == 0) {
				fprintf(stderr,
				    "duplicate controller name %s\n",
				    cp->name);
				exit(1);
			}
		}
	}

	if (get_obj_obj(cfg, "networks", &arr)) {
		netperm **npp = &netperms;
		netperm * np;
		char *    s;
		char *    ep;
		bool      allow;
		uint64_t  nwid;

		for (int i = 0; i < get_arr_len(arr); i++) {
			if (!get_arr_string(arr, i, &s)) {
				fprintf(stderr, "network %d malformed\n", i);
				exit(1);
			}
			if (*s == '+') {
				s++;
				allow = true;
			} else if (*s == '-') {
				s++;
				allow = false;
			} else {
				allow = true;
			}
			if (strcmp(s, "all")) {
				nwid = 0;
			} else if (((nwid = strtoull(s, &ep, 16)) == 0) ||
			    (*ep != '\0')) {
				fprintf(stderr, "network %d malformed\n", i);
				exit(1);
			}
			if ((np = malloc(sizeof(netperm))) == NULL) {
				fprintf(stderr, "out of memory\n");
				exit(1);
			}
			np->nwid  = nwid;
			np->allow = allow;
			np->next  = NULL;
			*npp      = np;
			npp       = &np;
		}
	}

	// TLS can be missing.
	if (get_obj_obj(cfg, "tls", &obj)) {
		int               rv;
		char *            key;
		char *            str;
		bool              insecure;
		nng_tls_auth_mode amode;

		if ((rv = nng_tls_config_alloc(&tls, NNG_TLS_MODE_CLIENT)) !=
		    0) {
			fprintf(stderr, "%s\n", nng_strerror(rv));
			exit(1);
		}
		str = NULL;
		get_obj_string(obj, "keypass", &str);
		if ((get_obj_string(obj, "keyfile", &key)) &&
		    ((rv = nng_tls_config_cert_key_file(tls, key, str)) !=
		        0)) {
			fprintf(stderr, "TLS keyfile: %s\n", nng_strerror(rv));
			exit(1);
		}
		if (get_obj_string(obj, "cacert", &str) &&
		    ((rv = nng_tls_config_ca_file(tls, str)) != 0)) {
			fprintf(stderr, "TLS cacert: %s\n", nng_strerror(rv));
			exit(1);
		}
		amode = NNG_TLS_AUTH_MODE_REQUIRED;
		if (get_obj_bool(obj, "insecure", &insecure) && insecure) {
			amode = NNG_TLS_AUTH_MODE_NONE;
		}
		if ((rv = nng_tls_config_auth_mode(tls, amode)) != 0) {
			fprintf(stderr, "%s\n", nng_strerror(rv));
			exit(1);
		}
	}

	// These might be missing. Note that if they are, they don't
	// overwrite values.
	(void) get_obj_string(cfg, "userdb", &userdb);
	(void) get_obj_string(cfg, "tokendb", &tokendb);
	(void) get_obj_string(cfg, "zthome", &zthome);
	(void) get_obj_int(cfg, "workers", &nworkers);

	if (nworkers < 1) {
		fprintf(stderr, "workers must be positive\n");
		exit(1);
	}
}

static void
free_config(worker_config *wc)
{
	if (wc != NULL) {
		free_obj(wc->json);
		free(wc->proxies);
		free(wc->controllers);
		free(wc->roles);
		free(wc->apis);
		free(wc->nets);
		free(wc);
	}
}
// This macro makes us do asprintf conditionally.
#define ERRF(strp, fmt, ...) \
	if (strp != NULL)    \
	asprintf(strp, fmt, ##__VA_ARGS__)

static worker_config *
load_config2(const char *path, char **errmsg)
{
	object *       obj;
	object *       arr;
	worker_config *wc;

	if ((wc = calloc(1, sizeof(worker_config))) == NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		return (NULL);
	}
	if ((wc->json = obj_load(path, errmsg)) == NULL) {
		free_config(wc);
		return (NULL);
	}

	if (get_obj_obj(wc->json, "roles", &arr)) {
		uint64_t mask;
		int      i;
		if (!is_obj_array(arr)) {
			ERRF(errmsg, "roles must be array");
			free_config(wc);
			return (NULL);
		}
		if ((wc->nroles = get_arr_len(arr)) > 64) {
			ERRF(errmsg, "too many roles");
			free_config(wc);
			return (NULL);
		}
		if ((wc->roles = calloc(sizeof(role_config), wc->nroles)) ==
		    NULL) {
			ERRF(errmsg, "calloc: %s", strerror(errno));
			free_config(wc);
			return (NULL);
		}
		mask = 1;
		for (i = 0; i < get_arr_len(arr); i++) {
			role_config *r = &wc->roles[i];
			if (!get_arr_string(arr, i, &r->name)) {
				ERRF(errmsg, "roles must be array of strings");
				free_config(wc);
				return (NULL);
			}
			// alphnumeric + _ for role names.  We want to reserve
			// other characters for future special purposes.
			for (int j = 0; j < strlen(r->name); j++) {
				if ((!isalnum(r->name[j])) &&
				    (r->name[j] != '_')) {
					ERRF(errmsg, "invalid role name");
					free_config(wc);
					return (NULL);
				}
			}
			for (int j = 0; j < i; j++) {
				if (strcmp(r->name, wc->roles[j].name) == 0) {
					ERRF(errmsg, "duplicate role name %s",
					    r->name);
					free_config(wc);
					return (NULL);
				}
			}
		}
	} else {
		wc->nroles = 0;
	}

	if ((!get_obj_obj(wc->json, "proxies", &arr)) ||
	    (!is_obj_array(arr))) {
		ERRF(errmsg, "missing proxies array");
		free_config(wc);
		return (NULL);
	}

	wc->nproxies = get_arr_len(arr);
	if ((wc->proxies = calloc(sizeof(proxy_config), wc->nproxies)) ==
	    NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		free_config(wc);
		return (NULL);
	}

	for (int i = 0; i < nproxies; i++) {
		object *      arr2;
		proxy_config *pp = &wc->proxies[i];

		if ((!get_arr_obj(arr, i, &obj)) ||
		    (!get_obj_string(obj, "survey", &pp->survurl)) ||
		    (!get_obj_string(obj, "reqrep", &pp->rpcurl))) {
			ERRF(errmsg, "proxy %d malformed", i);
			free_config(wc);
			return (NULL);
		}
		pp->nworkers = 4;
		if (get_obj_int(obj, "workers", &pp->nworkers) &&
		    ((nworkers < 1) || (nworkers > 1024))) {
			ERRF(errmsg, "proxy %d invalid worker count", i);
			free_config(wc);
			return (NULL);
		}

		// load in roles for proxy
		pp->roles = 0;
		if (get_obj_obj(obj, "roles", &arr2)) {
			for (int j = 0; j < get_arr_len(arr2); j++) {
				char *   s;
				uint64_t mask;
				if ((!get_arr_string(arr2, j, &s)) ||
				    ((mask = find_role_ext(wc, s)) == 0)) {
					ERRF(errmsg, "proxy %d bad role", i);
					free_config(wc);
					return (NULL);
				}
				pp->roles |= mask;
			}
		}
	}

	// Look up the list of controllers.
	if ((!get_obj_obj(wc->json, "controllers", &arr)) ||
	    ((wc->ncontrollers = get_arr_len(arr)) < 1)) {

		ERRF(errmsg, "no controllers supplied");
		free_config(wc);
		return (NULL);
	}
	wc->controllers = calloc(sizeof(controller_config), wc->ncontrollers);
	if (wc->controllers == NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		free_config(wc);
		return (NULL);
	}

	for (int i = 0; i < wc->ncontrollers; i++) {
		controller_config *cp = &wc->controllers[i];
		char *             ct;

		if ((!get_arr_obj(arr, i, &obj)) ||
		    (!get_obj_string(obj, "address", &cp->url)) ||
		    (!get_obj_string(obj, "secret", &cp->secret)) ||
		    (!get_obj_string(obj, "name", &cp->name))) {
			ERRF(errmsg, "controller %d incomplete", i);
			free_config(wc);
			return (NULL);
		}
		cp->central = false;
		if ((get_obj_string(obj, "type", &ct)) &&
		    (strcmp(ct, "central") == 0)) {
			// Fall back to default "controller"
			cp->central = true;
		}

		if (!valid_name(cp->name)) {
			ERRF(errmsg, "invalid controller name %d", i);
			free_config(wc);
			return (NULL);
		}

		for (int j = 0; j < i; j++) {
			if (strcmp(cp->name, wc->controllers[j].name) == 0) {
				ERRF(errmsg, "duplicate controller name %s",
				    cp->name);
				free_config(wc);
				return (NULL);
			}
		}
	}

#if 0
	// WE need to review the filtering of the API and network
	// configuration objects.
	if (get_obj_obj(cfg, "networks", &arr)) {
		netperm **npp = &netperms;
		netperm * np;
		char *    s;
		char *    ep;
		bool      allow;
		uint64_t  nwid;

		for (int i = 0; i < get_arr_len(arr); i++) {
			if (!get_arr_string(arr, i, &s)) {
				fprintf(stderr, "network %d malformed\n", i);
				exit(1);
			}
			if (*s == '+') {
				s++;
				allow = true;
			} else if (*s == '-') {
				s++;
				allow = false;
			} else {
				allow = true;
			}
			if (strcmp(s, "all")) {
				nwid = 0;
			} else if (((nwid = strtoull(s, &ep, 16)) == 0) ||
			    (*ep != '\0')) {
				fprintf(stderr, "network %d malformed\n", i);
				exit(1);
			}
			if ((np = malloc(sizeof(netperm))) == NULL) {
				fprintf(stderr, "out of memory\n");
				exit(1);
			}
			np->nwid  = nwid;
			np->allow = allow;
			np->next  = NULL;
			*npp      = np;
			npp       = &np;
		}
	}
#endif

	// TLS can be missing.
	if (get_obj_obj(wc->json, "tls", &obj)) {
		get_obj_string(obj, "keypass", &wc->tls.keypass);
		get_obj_string(obj, "keyfile", &wc->tls.keyfile);
		get_obj_string(obj, "cacert", &wc->tls.cacert);
		get_obj_bool(obj, "insecure", &wc->tls.insecure);

		if ((wc->tls.keyfile) && (!path_exists(wc->tls.keyfile))) {
			ERRF(errmsg, "keyfile does not exist");
			free_config(wc);
			return (NULL);
		}
		if ((wc->tls.cacert) && (!path_exists(wc->tls.cacert))) {
			ERRF(errmsg, "cacert does not exist");
			free_config(wc);
			return (NULL);
		}
	}
	if ((!get_obj_string(wc->json, "userdir", &wc->userdir)) ||
	    (!path_exists(wc->userdir))) {
		ERRF(errmsg, "userdir missing or does not exist");
		free_config(wc);
		return (NULL);
	}
	if ((!get_obj_string(wc->json, "tokendir", &wc->tokendir)) ||
	    (!path_exists(wc->tokendir))) {
		ERRF(errmsg, "tokendir missing or does not exist");
		free_config(wc);
		return (NULL);
	}

	// zthome is optional, but recommended.  If not used,
	// then an ephemeral ZeroTier node will be used.
	(void) get_obj_string(wc->json, "zthome", &wc->zthome);
	return (wc);
}

static nng_optspec opts[] = {
	{ "cfg", 'c', 'c', true },
	{ "debug", 'd', 'd', false },
};

int
main(int argc, char **argv)
{
	int         optc;
	char *      opta;
	int         opti = 1;
	const char *path = CONFIG;
	int         rv;

	while (nng_opts_parse(argc, argv, opts, &optc, &opta, &opti) == 0) {
		switch (optc) {
		case 'c':
			path = opta;
			break;
		case 'd':
			debug++;
			break;
		}
	}

	if ((rv = nng_zt_register()) != 0) {
		fprintf(stderr, "Failed to register ZT transport: %s\n",
		    nng_strerror(rv));
	}

	load_config(path);

	setup_controllers();

	setup_proxies();

	start_workers();

	if (debug) {
		printf("Waiting for requests...\n");
	}

	survey_loop();
	exit(0);
}
