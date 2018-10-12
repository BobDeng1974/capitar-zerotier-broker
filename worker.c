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
#include "otp.h"
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

// This macro makes us do asprintf conditionally.
#define ERRF(strp, fmt, ...) \
	if (strp != NULL)    \
	asprintf(strp, fmt, ##__VA_ARGS__)

static worker_config *cfg;

int debug;

typedef enum {
	STATE_RECVING,
	STATE_HTTPING,
	STATE_REPLYING,
} worker_state;

typedef struct proxy   proxy;
typedef struct netperm netperm;

nng_tls_config *tls = NULL;

struct worker {
	proxy *          proxy;
	nng_ctx          ctx; // REP context
	nng_http_req *   req;
	nng_http_res *   res;
	nng_aio *        aio;
	worker_state     state;
	nng_http_client *client;
	uint64_t         id; // request ID of pending request
	worker_http_cb   http_cb;
	const char *     method; // RPC method called
	uint64_t         user_roles;
	uint64_t         eff_roles; // roles as modified by proxy changes
};

struct controller {
	char *             addr;
	char *             name;
	char *             secret;
	char *             host; // for HTTP
	nng_http_client *  client;
	worker_ops *       ops;
	controller_config *config;
};

struct proxy {
	nng_socket    survsock;
	nng_socket    repsock;
	uint32_t      repport;
	worker *      workers;
	nng_aio *     survaio;
	int           state; // 0 - receiving, 1 sending
	proxy_config *config;
};

struct netperm {
	uint64_t nwid;
	bool     allow;
	netperm *next;
};

controller *controllers;
proxy *     proxies;

netperm *netperms;

static worker_ops *find_worker_ops(const char *);

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
survey_cb(void *arg)
{
	proxy *  p = arg;
	nng_msg *msg;
	int      rv;
	char *   body;
	object * obj;
	object * arr;

	if ((rv = nng_aio_result(p->survaio)) == NNG_ECLOSED) {
		// This only happens if the respondent socket is closed.
		// If so we want to bail out asap.
		return;
	}

	switch (p->state) {
	case 0: // receiving
		if (rv != 0) {
			// Failure receiving for some reason.  Try again.
			nng_recv_aio(p->survsock, p->survaio);
			return;
		}
		break;

	case 1: // sending
		if (rv != 0) {
			// Failed send, so just discard it.
			msg = nng_aio_get_msg(p->survaio);
			nng_aio_set_msg(p->survaio, NULL);
			nng_msg_free(msg);
		}
		p->state = 0;
		nng_recv_aio(p->survsock, p->survaio);
		return;
	}

	msg  = nng_aio_get_msg(p->survaio);
	body = NULL;
	arr  = alloc_arr();
	obj  = alloc_obj();
	nng_msg_clear(msg);

	if (((arr == NULL) || (obj == NULL)) ||
	    (!add_obj_int(obj, "port", (int) p->repport))) {
		goto fail;
	}

	for (int i = 0; i < cfg->ncontrollers; i++) {
		if (!add_arr_string(arr, controllers[i].config->name)) {
			goto fail;
		}
	}
	if (!add_obj_obj(obj, "controllers", arr)) {
		goto fail;
	}
	arr = NULL;

	if (((body = print_obj(obj)) == NULL) ||
	    (nng_msg_append(msg, body, strlen(body)) != 0)) {
		goto fail;
	}

	free(body);
	free_obj(obj);
	p->state = 1;
	nng_aio_set_msg(p->survaio, msg);
	nng_send_aio(p->survsock, p->survaio);
	return;

fail:
	nng_msg_free(msg);
	free(body);
	free_obj(obj);
	free_obj(arr);
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
		case E_AUTHREQD:
			rsn = "Authentication required";
			break;
		case E_AUTHFAIL:
			rsn = "Authentication failed";
			break;
		case E_AUTHOTP:
			rsn = "One-time password required";
			break;
		case E_AUTHTOKEN:
			rsn = "Bearer token invalid";
			break;
		case E_AUTHEXPIRE:
			rsn = "Bearer token expired";
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

extern void get_status(worker *, object *);
extern void get_networks(worker *, object *);
extern void get_network(worker *, object *);
extern void get_network_members(worker *, object *);
extern void get_network_member(worker *, object *);
extern void delete_network_member(worker *, object *);
extern void authorize_network_member(worker *, object *);
extern void deauthorize_network_member(worker *, object *);

static void create_auth_token(worker *, object *);
static void delete_auth_token(worker *, object *);
static void get_auth_token(worker *, object *);
static void get_auth_tokens(worker *, object *);
static void set_own_password(worker *, object *);
static void create_own_totp(worker *, object *);
static void delete_own_totp(worker *, object *);

static struct {
	const char *method;
	void (*func)(worker *, object *);
} jsonrpc_methods[] = {
	{ METHOD_GET_STATUS, get_status },
	{ METHOD_LIST_NETWORKS, get_networks },
	{ METHOD_GET_NETWORK, get_network },
	{ METHOD_LIST_MEMBERS, get_network_members },
	{ METHOD_GET_MEMBER, get_network_member },
	{ METHOD_DELETE_MEMBER, delete_network_member },
	{ METHOD_AUTH_MEMBER, authorize_network_member },
	{ METHOD_DEAUTH_MEMBER, deauthorize_network_member },
	{ METHOD_CREATE_TOKEN, create_auth_token },
	{ METHOD_DELETE_TOKEN, delete_auth_token },
	{ METHOD_GET_TOKEN, get_auth_token },
	{ METHOD_GET_TOKENS, get_auth_tokens },
	{ METHOD_SET_PASSWD, set_own_password },
	{ METHOD_CREATE_TOTP, create_own_totp },
	{ METHOD_DELETE_TOTP, delete_own_totp },
	{ NULL, NULL },
};

static void
jsonrpc(worker *w, object *reqobj, const char *meth, object *parm)
{
	// First check the general registered methods
	for (int i = 0; jsonrpc_methods[i].method != NULL; i++) {
		if (strcmp(jsonrpc_methods[i].method, meth) == 0) {
			w->method = meth; // save for auth checks
			jsonrpc_methods[i].func(w, parm);
			free_obj(reqobj);
			return;
		}
	}

	controller *cp;

	// Check the controller specific registered methods
	w->method = meth; // save for auth checks
	if (get_auth_param(w, parm, NULL) &&
	    get_controller_param(w, parm, &cp) &&
	    (cp->ops->exec_jsonrpc != NULL)) {
		cp->ops->exec_jsonrpc(cp, w, meth, parm);
		free_obj(reqobj);
		return;
	}

	free_obj(reqobj);
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

controller *
find_controller(worker *w, const char *name)
{
	for (int i = 0; i < cfg->ncontrollers; i++) {
		if (strcmp(controllers[i].config->name, name) == 0) {
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
	return (cp->config->secret);
}

const char *
get_controller_host(controller *cp)
{
	return (cp->host);
}

bool
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

bool
get_auth_param(worker *w, object *params, user **userp)
{
	char *  id;
	char *  pass;
	char *  otp;
	object *obj;
	user *  user;
	int     code;

	if (debug > 1) {
		printf("get_auth_param params: %s\n", print_obj(params));
	}
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
		if ((tok = find_token(id, &code, true)) == NULL) {
			send_err(w, code, NULL); // Invalid token.
			return (false);
		}

		w->eff_roles = token_roles(tok) | ROLE_ALL | ROLE_TOKEN;
		w->eff_roles |= w->proxy->config->role_add;
		w->eff_roles &= ~w->proxy->config->role_del;
		// User roles can be subtraced by proxy rules.
		w->user_roles = token_roles(tok) & ~w->proxy->config->role_del;

		if (!check_api_role(w->method, w->eff_roles)) {
			w->eff_roles  = 0;
			w->user_roles = 0;
			free_token(tok);
			send_err(w, E_FORBIDDEN, "Permission denied");
			return (false);
		}
		if ((userp != NULL) &&
		    ((*userp = dup_user(token_user(tok))) == NULL)) {
			free_token(tok);
			send_err(w, E_NOMEM, NULL);
			return (false);
		}

		free_token(tok);
		return (true);
	}

	otp = NULL;
	if ((!get_obj_string(obj, "user", &id)) ||
	    (!get_obj_string(obj, "pass", &pass))) {
		if (debug > 1) {
			printf("E_AUTHFAIL obj: %s\n", print_obj(obj));
		}
		send_err(w, E_AUTHFAIL, NULL);
		return (false);
	}
	get_obj_string(obj, "otp", &otp);
	if ((user = auth_user(id, pass, otp, &code)) == NULL) {
		send_err(w, code, NULL);
		return (false);
	}
	w->eff_roles = user_roles(user) | ROLE_ALL;
	w->eff_roles |= w->proxy->config->role_add;
	w->eff_roles &= ~w->proxy->config->role_del;
	// User roles can be subtraced by proxy rules.
	w->user_roles = user_roles(user) & ~w->proxy->config->role_del;
	w->user_roles &= ~w->proxy->config->role_del;

	if (!check_api_role(w->method, w->eff_roles)) {
		w->eff_roles  = 0;
		w->user_roles = 0;
		free_user(user);
		send_err(w, E_FORBIDDEN, "Permission denied");
		return (false);
	}

	if (userp == NULL) {
		free_user(user);
	} else {
		*userp = user;
	}
	return (true);
}

static void
create_auth_token(worker *w, object *params)
{
	uint64_t authroles, reqroles, mask;
	user *   u;
	token *  tok;
	object * a;
	object * result;
	char *   desc;
	double   expire;

	if (!get_auth_param(w, params, &u)) {
		return;
	}
	// authroles are the "inheritable" roles for a user.
	// It specifically excludes "%all", "%token", and roles that
	// were granted by the proxy accessed.  %admin will be treated
	// like other roles for inheritance purposes.
	authroles = w->user_roles;
	if (get_obj_obj(params, "roles", &a)) {
		reqroles = 0;
		for (int i = 0; i < get_arr_len(a); i++) {
			char *   n;
			uint64_t val;
			if (!get_arr_string(a, i, &n)) {
				free_user(u);
				send_err(w, E_BADPARAMS, NULL);
				return;
			}
			// Make sure that the requested role is one the
			// client already has.  This also covers the case
			// for invalid role names.
			val = find_role(n);
			if ((val & authroles) == 0) {
				free_user(u);
				send_err(w, E_FORBIDDEN,
				    "No permission for requested role");
			}
			reqroles |= val;
		}
	} else {
		reqroles = authroles;
	}

	desc = "api token";
	// If a name is supplied, lets use it.
	get_obj_string(params, "desc", &desc);

	// Note: there is no limit on the length of token expiration at
	// this point.  We could add that as a tunable, and set it.
	// We could also provide a default expiration time here.
	expire = 0;
	get_obj_number(params, "expires", &expire);

	if ((tok = create_token(u, desc, expire, reqroles)) == NULL) {
		send_err(w, E_INTERNAL, "Failed to create auth token");
		free_user(u);
		return;
	}
	free_user(u);

	if ((a = alloc_arr()) == NULL) {
		free_token(tok);
		send_err(w, E_NOMEM, NULL);
		return;
	}

	mask     = 1;
	reqroles = token_roles(tok);
	for (int i = 0; i < 64; i++, mask <<= 1) {
		const char *name;
		if ((reqroles & mask) == 0) {
			continue;
		}
		if ((name = role_name(mask)) == NULL) {
			continue;
		}
		if (!add_arr_string(a, name)) {
			free_token(tok);
			free_obj(a);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}

	if (((result = alloc_obj()) == NULL) ||
	    (!add_obj_string(result, "id", token_id(tok))) ||
	    (!add_obj_string(result, "desc", token_desc(tok))) ||
	    (!add_obj_number(result, "created", token_created(tok))) ||
	    (!add_obj_number(result, "expires", token_expires(tok))) ||
	    (!add_obj_obj(result, "roles", a))) {
		send_err(w, E_NOMEM, NULL);
		free_obj(result);
		free_obj(a);
		delete_token(tok);
		return;
	}
	send_result(w, result);
}

static void
get_auth_token(worker *w, object *params)
{
	uint64_t roles;
	uint64_t mask;
	user *   u;
	token *  tok;
	object * a;
	object * result;
	char *   desc;
	double   expire;
	char *   id;
	int      code;

	if (!get_auth_param(w, params, &u)) {
		return;
	}
	if (!get_obj_string(params, "token", &id)) {
		free_user(u);
		send_err(w, E_BADPARAMS, NULL);
		return;
	}

	if (((tok = find_token(id, &code, false)) == NULL) ||
	    (!token_belongs(tok, u))) {
		free_token(tok);
		free_user(u);
		send_err(w, 404, "No such token");
		return;
	}
	free_user(u);

	if ((a = alloc_arr()) == NULL) {
		free_token(tok);
		send_err(w, E_NOMEM, NULL);
		return;
	}

	mask  = 1;
	roles = token_roles(tok);
	for (int i = 0; i < 64; i++, mask <<= 1) {
		const char *name;
		if ((roles & mask) == 0) {
			continue;
		}
		if ((name = role_name(mask)) == NULL) {
			continue;
		}
		if (!add_arr_string(a, name)) {
			free_token(tok);
			free_obj(a);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}

	// Should we expose the token's user?  It is our own name, so for
	// now we aren't doing it.
	if (((result = alloc_obj()) == NULL) ||
	    (!add_obj_string(result, "id", token_id(tok))) ||
	    (!add_obj_string(result, "desc", token_desc(tok))) ||
	    (!add_obj_number(result, "expires", token_expires(tok))) ||
	    (!add_obj_number(result, "created", token_created(tok))) ||
	    (!add_obj_obj(result, "roles", a))) {
		free_obj(a);
		free_obj(result);
		free_token(tok);
		send_err(w, E_NOMEM, NULL);
		delete_token(tok);
		return;
	}
	send_result(w, result);
}

static void
delete_auth_token(worker *w, object *params)
{
	user *  u;
	token * tok;
	object *result;
	char *  id;
	int     code;

	if (!get_auth_param(w, params, &u)) {
		return;
	}
	if (!get_obj_string(params, "token", &id)) {
		free_user(u);
		send_err(w, E_BADPARAMS, NULL);
		return;
	}

	// We don't allow users to delete tokens they don't own!
	if (((tok = find_token(id, &code, false)) == NULL) ||
	    (!token_belongs(tok, u))) {
		free_token(tok);
		free_user(u);
		send_err(w, 404, "No such token");
		return;
	}

	free_user(u);
	if ((result = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	delete_token(tok);
	send_result(w, result);
}

static void
get_auth_tokens(worker *w, object *params)
{
	user *  u;
	token **toks;
	int     ntoks;
	object *result;

	if (!get_auth_param(w, params, &u)) {
		return;
	}
	if (!user_tokens(u, &toks, &ntoks)) {
		free_user(u);
		send_err(w, E_NOMEM, NULL); // generally
		return;
	}
	free_user(u);
	if ((result = alloc_arr()) == NULL) {
		free_tokens(toks, ntoks);
		send_err(w, E_NOMEM, NULL); // generally
		return;
	}
	for (int i = 0; i < ntoks; i++) {
		if (!add_arr_string(result, token_id(toks[i]))) {
			free_tokens(toks, ntoks);
			free_obj(result);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}
	free_tokens(toks, ntoks);

	send_result(w, result);
}

static void
set_own_password(worker *w, object *params)
{
	user *  u;
	char *  pass;
	object *result;

	if (!get_auth_param(w, params, &u)) {
		return;
	}
	if (!get_obj_string(params, "password", &pass)) {
		send_err(w, E_BADPARAMS, NULL);
		return;
	}
	if ((result = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
		free_user(u);
		return;
	}
	if (!set_password(u, pass)) {
		free_user(u);
		free_obj(result);
		send_err(w, E_NOMEM, NULL); // generally
		return;
	}
	free_user(u);
	send_result(w, result);
}

static bool
urlsafe(char c)
{
	if (isalnum(c)) {
		return (true);
	}
	if (strchr("$-_.+!*'(),", c) != NULL) {
		return (true);
	}
	return (false);
}

static char *
urlencode(const char *in)
{
	size_t l = 0;
	char * buf;
	char * dst;
	char   c;
	for (int i = 0; (c = in[i]) != '\0'; i++) {
		l += urlsafe(c) ? 1 : 3;
	}
	if ((buf = malloc(l + 1)) == NULL) {
		return (NULL);
	}
	dst = buf;
	for (int i = 0; (c = in[i]) != '\0'; i++) {
		if (urlsafe(c)) {
			*dst++ = c;
		} else {
			char hex[3];
			*dst++ = '%';
			snprintf(hex, 3, "%02X", c);
			*dst++ = hex[0];
			*dst++ = hex[1];
		}
	}
	*dst = '\0';
	return (buf);
}

static void
create_own_totp(worker *w, object *params)
{
	user *       u;
	char *       issuer;
	object *     result;
	char *       url;
	const otpwd *o;
	char *       ibuf = NULL;
	char *       ubuf = NULL;

	if (!get_auth_param(w, params, &u)) {
		return;
	}

	if (!get_obj_string(params, "issuer", &issuer)) {
		send_err(w, E_BADPARAMS, NULL);
		return;
	}
	if (((result = alloc_obj()) == NULL) ||
	    ((ibuf = urlencode(issuer)) == NULL) ||
	    ((ubuf = urlencode(user_name(u))) == NULL)) {
		send_err(w, E_NOMEM, NULL);
		free_obj(result);
		free(ibuf);
		free_user(u);
		return;
	}
	if ((!create_totp(u, issuer)) || ((o = user_otpwd(u, 0)) == NULL)) {
		send_err(w, E_NOMEM, NULL);
		free_obj(result);
		free_user(u);
		return;
	}
	// URL encode unsafe characters into buf

	if (asprintf(&url,
	        "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
	        ibuf, ubuf, otpwd_secret(o), ibuf, otpwd_digits(o),
	        otpwd_period(o)) < 0) {
		free_user(u);
		free_obj(result);
		free(ibuf);
		free(ubuf);
		send_err(w, E_NOMEM, NULL); // generally
		return;
	}

	free(ibuf);
	free(ubuf);

	if ((!add_obj_string(result, "issuer", otpwd_name(o))) ||
	    (!add_obj_string(result, "type", otpwd_type(o))) ||
	    (!add_obj_string(result, "algorithm", "SHA1")) ||
	    (!add_obj_number(result, "digits", otpwd_digits(o))) ||
	    (!add_obj_number(result, "period", otpwd_period(o))) ||
	    (!add_obj_string(result, "secret", otpwd_secret(o))) ||
	    (!add_obj_string(result, "url", url))) {
		free_user(u);
		free(url);
		free_obj(result);
		send_err(w, E_NOMEM, NULL); // generally
		return;
	}
	free(url);
	free_user(u);
	send_result(w, result);
}

static void
delete_own_totp(worker *w, object *params)
{
	user *       u;
	char *       issuer;
	object *     result;
	char *       url;
	const otpwd *o;
	char *       ibuf = NULL;
	char *       ubuf = NULL;

	if (!get_auth_param(w, params, &u)) {
		return;
	}

	if ((result = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
		free_user(u);
		return;
	}
	if (!delete_totp(u)) {
		send_err(w, E_NOMEM, NULL);
		free_obj(result);
		free_user(u);
		return;
	}
	free_user(u);
	send_result(w, result);
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
		if (debug > 1) {
			printf("http_cb nng_aio_result err: %s\n",
			    nng_strerror(rv));
		}
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
start_proxies(worker_config *wc)
{
	for (int i = 0; i < wc->nproxies; i++) {
		proxy *p = &proxies[i];
		nng_recv_aio(p->survsock, p->survaio);

		for (int j = 0; j < p->config->nworkers; j++) {
			worker *w = &p->workers[j];
			recv_request(w);
		}
	}
}
static bool
setup_controller(worker_config *wc, controller *cp, char **errmsg)
{
	int      rv;
	nng_url *url = NULL;

	// Allocate an HTTP client.  We can reuse the client.
	if (((rv = nng_url_parse(&url, cp->config->url)) != 0) ||
	    ((rv = nng_http_client_alloc(&cp->client, url)) != 0)) {
		ERRF(errmsg, "controller: %s", nng_strerror(rv));
		nng_url_free(url);
		return (false);
	}

	if (((strcmp(url->u_scheme, "http") == 0) &&
	        (strcmp(url->u_port, "80") == 0)) ||
	    ((strcmp(url->u_scheme, "https") == 0) &&
	        (strcmp(url->u_port, "443") == 0))) {
		cp->host = strdup(url->u_host);
	} else {
		cp->host = strdup(url->u_hostname);
	}
	nng_url_free(url);
	if (cp->host == NULL) {
		ERRF(errmsg, "strdup: %s", strerror(ENOMEM));
		return (false);
	}

	if (strncmp(cp->config->url, "https", 5) == 0) {
		if (tls == NULL) {
			ERRF(errmsg, "controller: missing TLS config");
			return (false);
		}
		if ((rv = nng_http_client_set_tls(cp->client, tls)) != 0) {
			ERRF(errmsg, "controller TLS: %s", nng_strerror(rv));
			return (false);
		}
	}
	if ((cp->ops = find_worker_ops(cp->config->type)) == NULL) {
		ERRF(errmsg, "controller: unable to find ops vector");
		return (false);
	}
	return (true);
}

static bool
setup_controllers(worker_config *wc, char **errmsg)
{
	if ((controllers = calloc(sizeof(controller), wc->ncontrollers)) ==
	    NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		return (false);
	}
	for (int i = 0; i < wc->ncontrollers; i++) {
		controllers[i].config = &wc->controllers[i];
		if (!setup_controller(wc, &controllers[i], errmsg)) {
			for (int j = 0; j < i; j++) {
				nng_http_client_free(controllers[i].client);
				free(controllers[i].host);
			}
			free(controllers);
			controllers = NULL;
			return (false);
		}
	}
	return (true);
}

static bool
setup_proxy(worker_config *wc, proxy *p, char **errmsg)
{
	int          rv;
	nng_listener l;
	nng_sockaddr sa;
	nng_socket   s;
	char *       url;

	memset(&s, 0, sizeof(s));
	if (((rv = nng_rep0_open(&s)) != 0) ||
	    (((wc->zthome != NULL) &&
	        (rv = nng_setopt_string(s, NNG_OPT_ZT_HOME, wc->zthome)) !=
	            0)) ||
	    ((rv = nng_setopt_ms(s, NNG_OPT_ZT_PING_TIME, 1000)) != 0) ||
	    ((rv = nng_listen(s, p->config->rpcurl, &l, 0)) != 0)) {
		ERRF(errmsg, "rep(%s): %s", p->config->rpcurl,
		    nng_strerror(rv));
		nng_close(s);
		nng_aio_free(p->survaio);
		p->survaio = NULL;
		return (false);
	}

	if (((rv = nng_listener_getopt_sockaddr(l, NNG_OPT_LOCADDR, &sa)) !=
	        0) ||
	    ((rv = nng_listener_getopt_string(l, NNG_OPT_URL, &url)) != 0)) {
		ERRF(errmsg, "listener_getopt: %s", nng_strerror(rv));
		nng_close(s);
		return (false);
	}

	p->repport = sa.s_zt.sa_port;
	p->repsock = s;
	printf("REP listening at %s\n", url);

	memset(&s, 0, sizeof(s));
	if (((rv = nng_aio_alloc(&p->survaio, survey_cb, p)) != 0) ||
	    ((rv = nng_respondent0_open(&s)) != 0) ||
	    (((wc->zthome != NULL) &&
	        (rv = nng_setopt_string(s, NNG_OPT_ZT_HOME, wc->zthome)) !=
	            0)) ||
	    ((rv = nng_setopt_ms(s, NNG_OPT_ZT_PING_TIME, 1000)) != 0) ||
	    ((rv = nng_setopt_ms(s, NNG_OPT_ZT_CONN_TIME, 1000)) != 0) ||
	    ((rv = nng_setopt_ms(s, NNG_OPT_RECONNMINT, 1)) != 0) ||
	    ((rv = nng_setopt_ms(s, NNG_OPT_RECONNMAXT, 10)) != 0) ||
	    ((rv = nng_dial(s, p->config->survurl, NULL, NNG_FLAG_NONBLOCK)) !=
	        0)) {
		ERRF(errmsg, "respondent: %s", nng_strerror(rv));
		nng_close(p->repsock);
		nng_close(s);
		return (false);
	}
	p->survsock = s;
	printf("RESPONDENT dialing to %s\n", p->config->survurl);

	if ((p->workers = calloc(p->config->nworkers, sizeof(worker))) ==
	    NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		return (false);
	}
	for (int i = 0; i < p->config->nworkers; i++) {
		worker *w = &p->workers[i];
		w->proxy  = p;

		if (((rv = nng_aio_alloc(&w->aio, worker_cb, w)) != 0) ||
		    ((rv = nng_http_req_alloc(&w->req, NULL)) != 0) ||
		    ((rv = nng_http_res_alloc(&w->res)) != 0) ||
		    ((rv = nng_ctx_open(&w->ctx, p->repsock)) != 0)) {
			ERRF(errmsg, "worker init: %s", nng_strerror(rv));
			nng_close(p->repsock);
			nng_close(p->survsock);
			return (false);
		}
	}

	return (true);
}

static bool
setup_proxies(worker_config *wc, char **errmsg)
{
	if ((proxies = calloc(sizeof(proxy), wc->nproxies)) == NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		return (false);
	}
	for (int i = 0; i < wc->nproxies; i++) {
		proxies[i].config = &wc->proxies[i];
		if (!setup_proxy(wc, &proxies[i], errmsg)) {
			for (int j = 0; j < i; j++) {
				nng_close(proxies[j].survsock);
				nng_close(proxies[j].repsock);
			}
			free(proxies);
			proxies = NULL;
			return (false);
		}
	}
	return (true);
}

static bool
setup_tls(worker_config *wc, char **errmsg)
{
	nng_tls_config *tc;
	nng_tls_config *old;
	int             rv;
	int             amode;

	if ((rv = nng_tls_config_alloc(&tc, NNG_TLS_MODE_CLIENT)) != 0) {
		ERRF(errmsg, "tls_config_alloc: Out of memory");
		return (false);
	}
	if ((wc->tls.keyfile != NULL) &&
	    ((rv = nng_tls_config_cert_key_file(
	          tc, wc->tls.keyfile, wc->tls.keypass)) != 0)) {
		ERRF(errmsg, "TLS keyfile: %s", nng_strerror(rv));
		return (false);
	}

	if ((wc->tls.cacert != NULL) &&
	    ((rv = nng_tls_config_ca_file(tc, wc->tls.cacert)) != 0)) {
		ERRF(errmsg, "TLS cacert: %s", nng_strerror(rv));
		return (false);
	}
	amode = wc->tls.insecure ? NNG_TLS_AUTH_MODE_NONE
	                         : NNG_TLS_AUTH_MODE_REQUIRED;
	if ((rv = nng_tls_config_auth_mode(tc, amode)) != 0) {
		ERRF(errmsg, "TLS config_auth_mode: %s", nng_strerror(rv));
		return (false);
	}
	old = tls;
	tls = tc;
	if (old != NULL) {
		nng_tls_config_free(old);
	}
	return (true);
}

static bool
apply_config(worker_config *wc, char **errmsg)
{
	auth_init(wc);
	if ((!setup_tls(wc, errmsg)) || (!setup_proxies(wc, errmsg)) ||
	    (!setup_controllers(cfg, errmsg))) {
		return (false);
	}
	return (true);
}

typedef struct worker_ops_entry worker_ops_entry;
struct worker_ops_entry {
	const char *             name;
	worker_ops *             ops;
	struct worker_ops_entry *next;
};

worker_ops_entry *ops_types;

static worker_ops *
find_worker_ops(const char *name)
{
	worker_ops_entry *ent;
	// Default to controller_zt1.
	if ((name == NULL) || (*name == '\0')) {
		name = "zt1";
	}
	for (ent = ops_types; ent != NULL; ent = ent->next) {
		if (strcmp(ent->name, name) == 0) {
			return (ent->ops);
		}
	}
	return (NULL);
}

bool
worker_register_ops(worker_ops *ops)
{
	worker_ops_entry *ent;
	for (ent = ops_types; ent != NULL; ent = ent->next) {
		if (strcmp(ops->type, ent->name) == 0) {
			// already registered
			return (true);
		}
	}
	if (ops->version != WORKER_OPS_VERSION) {
		return (false);
	}
	if ((ent = malloc(sizeof(*ent))) == NULL) {
		return (false);
	}
	ent->next = ops_types;
	ent->name = ops->type;
	ent->ops  = ops;
	ops_types = ent;
	return (true);
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

static bool
parse_roles(worker_config *wc, object *arr, uint64_t *maskp, char **errmsg)
{
	uint64_t m = 0;
	uint64_t v;
	char *   n;
	for (int i = 0; i < get_arr_len(arr); i++) {
		if (!get_arr_string(arr, i, &n)) {
			ERRF(errmsg, "bad role array item at index %d", i);
			return (false);
		}
		if ((!check_role_name_configured(wc, n))) {
			ERRF(errmsg, "unknown role %s", n);
			return (false);
		}
		m |= v;
	}
	*maskp = m;
	return (true);
}

static worker_config *
load_config(const char *path, char **errmsg)
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

		// For now we are only permitting 32 roles.  The reason
		// is so that we can reserve up to 32 additional built-in
		// roles which are not configuration file driven.
		if ((wc->nroles = get_arr_len(arr)) > 32) {
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
			// Role names are required to start with an alpha
			// numeric or [_].  They furthermore must consist
			// entirely of printable characters.  Special role
			// names used by the system will start with other
			// characters.
			if ((!isalnum(r->name[0])) && (r->name[0] != '_')) {
				ERRF(errmsg, "invalid role name");
				free_config(wc);
				return (NULL);
			}
			for (int j = 0; j < r->name[j] != '\0'; j++) {
				if (!isprint(r->name[j])) {
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

	for (int i = 0; i < wc->nproxies; i++) {
		object *      rmod;
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
		    ((pp->nworkers < 1) || (pp->nworkers > 1024))) {
			ERRF(errmsg, "proxy %d invalid worker count", i);
			free_config(wc);
			return (NULL);
		}

		// load in roles for proxy
		pp->role_add = 0;
		pp->role_del = 0;
		if (get_obj_obj(obj, "rolemod", &rmod)) {
			object *roles;
			if ((get_obj_obj(rmod, "add", &roles)) &&
			    (!parse_roles(wc, roles, &pp->role_add, errmsg))) {
				free_config(wc);
				return (NULL);
			}
			if ((get_obj_obj(rmod, "del", &roles)) &&
			    (!parse_roles(wc, roles, &pp->role_del, errmsg))) {
				free_config(wc);
				return (NULL);
			}
		}
	}

	wc->napis = 0;
	if (get_obj_obj(wc->json, "api", &arr)) {
		char *key;
		int   i;
		for (key = next_obj_key(arr, NULL); key != NULL;
		     key = next_obj_key(arr, key)) {
			wc->napis++;
		}
		if ((wc->apis = calloc(sizeof(api_config), wc->napis)) ==
		    NULL) {
			ERRF(errmsg, "calloc: %s", strerror(errno));
			free_config(wc);
			return (NULL);
		}
		for (key = next_obj_key(arr, NULL), i = 0; key != NULL;
		     key = next_obj_key(arr, key), i++) {
			object *ao;
			object *roles;
			bool    valid;

			if (!get_obj_obj(arr, key, &ao)) {
				ERRF(errmsg, "api for %s invalid", key);
				free_config(wc);
				return (NULL);
			}
			wc->apis[i].method = key;
			wc->apis[i].allow  = 0;
			wc->apis[i].deny   = 0;

			if ((get_obj_obj(ao, "allow", &roles)) &&
			    (!parse_roles(
			        wc, roles, &wc->apis[i].allow, errmsg))) {
				free_config(wc);
				return (NULL);
			}
			if ((get_obj_obj(ao, "deny", &roles)) &&
			    (!parse_roles(
			        wc, roles, &wc->apis[i].deny, errmsg))) {
				free_config(wc);
				return (NULL);
			}
			for (int j = 0; j < i; j++) {
				if (strcmp(wc->apis[j].method, key) == 0) {
					ERRF(errmsg, "duplicate api %s", key);
					free_config(wc);
					return (NULL);
				}
			}
			valid = false;
			for (int j = 0; jsonrpc_methods[j].method; j++) {
				if (strcmp(jsonrpc_methods[j].method, key) ==
				    0) {
					valid = true;
					break;
				}
			}
			if (!valid) {
				ERRF(errmsg, "unknown method name %s", key);
				/* FIXME for controller specific methods
				free_config(wc);
				return (NULL);
				*/
			}
		}
	}

	wc->nnets = 0;
	if (get_obj_obj(wc->json, "network", &arr)) {
		char *   key;
		int      i;
		uint64_t nwid;
		for (key = next_obj_key(arr, NULL); key != NULL;
		     key = next_obj_key(arr, key)) {
			wc->nnets++;
		}
		if ((wc->nets = calloc(sizeof(net_config), wc->nnets)) ==
		    NULL) {
			ERRF(errmsg, "calloc: %s", strerror(errno));
			free_config(wc);
			return (NULL);
		}

		for (key = next_obj_key(arr, NULL), i = 0; key != NULL;
		     key = next_obj_key(arr, key), i++) {
			object *ao;
			object *roles;
			char *  ep;

			if (strcmp(key, "*") == 0) {
				wc->nets[i].nwid = 0;
			} else if (((wc->nets[i].nwid =
			                    strtoull(key, &ep, 16)) == 0) ||
			    (ep == key) || (*ep != '\0')) {
				ERRF(errmsg, "invalid network id %d", i);
				free_config(wc);
				return (NULL);
			}

			for (int j = 0; j < i; j++) {
				if (wc->nets[j].nwid == wc->nets[i].nwid) {
					ERRF(errmsg, "duplicate nwid %s", key);
					free_config(wc);
					return (NULL);
				}
			}
			if (!get_obj_obj(arr, key, &ao)) {
				ERRF(errmsg, "api for %s invalid", key);
				free_config(wc);
				return (NULL);
			}
			wc->nets[i].allow = 0;
			wc->nets[i].deny  = 0;
			if ((get_obj_obj(ao, "allow", &roles)) &&
			    (!parse_roles(
			        wc, roles, &wc->nets[i].allow, errmsg))) {
				free_config(wc);
				return (NULL);
			}
			if ((get_obj_obj(ao, "deny", &roles)) &&
			    (!parse_roles(
			        wc, roles, &wc->nets[i].deny, errmsg))) {
				free_config(wc);
				return (NULL);
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
		cp->type = "controller_zt1";
		get_obj_string(obj, "type", &cp->type);
		if (find_worker_ops(cp->type) == NULL) {
			ERRF(errmsg, "controller %d unknown type", i);
			free_config(wc);
			return (NULL);
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

	// TLS can be missing.
	if (get_obj_obj(wc->json, "tls", &obj)) {
		get_obj_string(obj, "keypass", &wc->tls.keypass);
		get_obj_string(obj, "keyfile", &wc->tls.keyfile);
		get_obj_string(obj, "cacert", &wc->tls.cacert);
		get_obj_bool(obj, "insecure", &wc->tls.insecure);

		if ((wc->tls.keyfile != NULL) &&
		    (!path_exists(wc->tls.keyfile))) {
			ERRF(errmsg, "keyfile does not exist");
			free_config(wc);
			return (NULL);
		}
		if ((wc->tls.cacert != NULL) &&
		    (!path_exists(wc->tls.cacert))) {
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
	char *      err;

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

	otptest(); // Run an internal self test.  This can be removed later.

	if ((!worker_register_ops(&controller_zt1_ops)) ||
	    (!worker_register_ops(&controller_ztcentral_ops))) {
		fprintf(stderr, "Failed to register worker ops\n");
		exit(1);
	}

	if ((rv = nng_zt_register()) != 0) {
		fprintf(stderr, "Failed to register ZT transport: %s\n",
		    nng_strerror(rv));
	}

	if ((cfg = load_config(path, &err)) == NULL) {
		fprintf(stderr, "Failed to load config: %s\n", err);
		exit(1);
	}

	if (!apply_config(cfg, &err)) {
		fprintf(stderr, "Failed to apply config: %s\n", err);
		exit(1);
	};

	start_proxies(cfg);

	if (debug) {
		printf("Waiting for requests...\n");
	}

	for (;;) {
		nng_msleep(3600000); // an hour
	}
	exit(0);
}
