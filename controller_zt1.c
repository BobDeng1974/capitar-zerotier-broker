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

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>

#include "object.h"
#include "util.h"
#include "worker.h"
#include "controller.h"
#include "auth.h"


extern nng_tls_config *tls;
extern worker_ops *    find_worker_ops(const char *);


static bool
zt1_init_req(controller *cp, worker *w, const char *fmt, ...)
{
	char          uri[256];
	nng_http_req *req;
	va_list       ap;

	req = worker_http_req(w);
	nng_http_req_reset(req);

	va_start(ap, fmt);
	vsnprintf(uri, sizeof(uri), fmt, ap);
	va_end(ap);

	if ((nng_http_req_set_uri(req, uri) != 0) ||
	    (nng_http_req_set_header(req, "Host", get_controller_host(cp)) !=
	        0) ||
	    (nng_http_req_set_header(
	         req, "X-ZT1-Auth", get_controller_secret(cp)) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return (false);
	}
	return (true);
}

static void
zt1_get_status_cb(worker *w, void *body, size_t len)
{
	object *obj;
	bool    b;

	if (((obj = parse_obj(body, len)) == NULL) ||
	    (!get_obj_bool(obj, "controller", &b)) || (!b)) {
		free_obj(obj);
		send_err(w, E_BADJSON, NULL);
		return;
	}
	free_obj(obj);
	if (((obj = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj, "version", RPC_VERSION)) ||
	    (!add_obj_bool(obj, "controller", true)) ||
	    (!add_obj_bool(obj, "central", false))) {
		free_obj(obj);
		send_err(w, E_NOMEM, NULL);
		return;
	}

	send_result(w, obj);
}

static void
zt1_create_network_cb(worker *w, void *body, size_t len)
{
	object   *obj;
	char     *username;
	uint64_t  tag;
        user     *u;
        char     *owner;
	int       errcode;
	char     *nwid;
	object   *nw;
	object   *nw2;
	object   *usernw;
	object   *usernw2;
	char     *nwtype;

	if ((obj = parse_obj(body, len)) == NULL) {
		send_err(w, E_BADJSON, NULL);
		return;
	}

	if (!valid_worker_session(w)) {
		return;
	}

	if ((!get_obj_string(w->session, "network_creator", &username)) ||
	     (!get_obj_uint64(w->session, "network_creator_tag", &tag)) ||
	     ((u = find_user(username)) == NULL) ||
             (u->tag != tag)) {
		if (u != NULL) {
			free_user(u);
		}
		send_err(w, E_NOTFOUND, "Cannot match network creator with user.");
		return;
	}
	free_user(u);

	owner = strdup(username);
	nwtype = "unknown";
	if (!get_obj_obj(w->session, "nwinfo", &nw)) {
		nw2 = alloc_obj();
	} else {
		nw2 = clone_obj(nw);
		get_obj_string(nw, "type", &nwtype);
		get_obj_string(nw, "owner", &owner);
	}

	if ((samestr(username, owner)) ||
	    (!check_api_role("create-user", w->eff_roles)) ||
	    ((u = find_user(owner)) == NULL)) {
		// Cannot set to intended user, so set to self
		u = find_user(username);
	}

	if (!get_obj_obj(u->json, "networks", &usernw)) {
		usernw2 = alloc_obj();
	} else {
		usernw2 = clone_obj(usernw);
	}

	if ((usernw2 == NULL) ||
	    (nw2 == NULL) ||
	    (!get_obj_string(obj, "id", &nwid)) ||
	    (!add_obj_obj(usernw2, nwid, nw2)) ||
	    (!add_obj_bool(nw2, "is_owner", true)) ||
	    (!add_obj_string(nw2, "type", nwtype)) ||
	    (!add_obj_string(nw2, "controller", w->controller)) ||
	    (!add_obj_obj(u->json, "networks", usernw2)) ||
	    (!save_user(u, &errcode))) {
		free_user(u);
		send_err(w, errcode, "Cannot register network to user.");
		return;
	}

	free_user(u);
	send_result(w, obj);
}

static void
zt1_create_network(controller *cp, worker *w, object *params)
{
	nng_http_req *req;
	char         *body;
	object       *nwconf;
	char         *name;

	if ((!get_obj_obj(params, "nwconf", &nwconf)) ||
	    (!get_obj_string(nwconf, "name", &name)) ||
	    (empty(name))) {
		send_err(w, E_BADPARAMS, "Name missing");
		return;
	}

	if (!zt1_init_req(cp, w, "/controller/network/%010llx______",
	    (unsigned long long) cp->config->nodeid)) {
		return;
	}
	req = worker_http_req(w);
	if ((nng_http_req_set_method(req, "POST") != 0) ||
	    ((body = print_obj(nwconf)) == NULL) ||
	    (nng_http_req_copy_data(req, body, strlen(body)) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, zt1_create_network_cb);
}

static void
zt1_get_status(controller *cp, worker *w)
{
	if (!zt1_init_req(cp, w, "/controller")) {
		return;
	}
	worker_http(w, zt1_get_status_cb);
}

static void
zt1_get_networks_cb(worker *w, void *body, size_t len)
{
	object *arr;
	object *arr2;
	object *obj2;

	if (((arr = parse_obj(body, len)) == NULL) || (!is_obj_array(arr))) {
		send_err(w, E_BADJSON, NULL);
		return;
	}
	if ((arr2 = alloc_arr()) == NULL) {
		free_obj(arr);
		send_err(w, E_NOMEM, NULL);
		return;
	}

	for (int i = 0; i < get_arr_len(arr); i++) {
		char *   s;
		char *   ep;
		uint64_t nwid;
		if ((!get_arr_string(arr, i, &s)) ||
		    ((nwid = strtoull(s, &ep, 16)) == 0) || (*ep != '\0')) {
			free_obj(arr);
			free_obj(arr2);
			send_err(w, E_BADJSON, NULL);
			return;
		}
		if (!check_nwid_role(nwid, w->eff_roles)) {
			continue;
		}
		if ((obj2 = alloc_obj()) == NULL) {
		       free_obj(arr);
		       free_obj(arr2);
		       send_err(w, E_NOMEM, NULL);
		       return;
		}
		if ((!add_obj_string(obj2, "id", s)) ||
		    (!add_arr_obj(arr2, obj2))) {
			free_obj(arr);
			free_obj(arr2);
			free_obj(obj2);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}
	free_obj(arr);
	send_result(w, arr2);
}

static void
zt1_get_networks(controller *cp, worker *w)
{
	if (!zt1_init_req(cp, w, "/controller/network")) {
		return;
	}

	worker_http(w, zt1_get_networks_cb);
}

static void
zt1_get_network_cb(worker *w, void *body, size_t len)
{
	object *obj1;
	object *obj2;
	object *obj3;
	char *  id;
	char *  name;
	bool    prv;
	bool    eb;
	int     mclim;
	double  crtime;
	object *v4am   = NULL;
	object *v6am   = NULL;
	object *routes = NULL;

	if (((obj1 = parse_obj(body, len)) == NULL) ||
	    (!get_obj_string(obj1, "id", &id)) ||
	    (!get_obj_string(obj1, "name", &name)) ||
	    (!get_obj_number(obj1, "creationTime", &crtime)) ||
	    (!get_obj_bool(obj1, "enableBroadcast", &eb)) ||
	    (!get_obj_int(obj1, "multicastLimit", &mclim)) ||
	    (!get_obj_obj(obj1, "routes", &obj3)) ||
	    ((routes = clone_obj(obj3)) == NULL) ||
	    (!get_obj_obj(obj1, "v4AssignMode", &obj3)) ||
	    ((v4am = clone_obj(obj3)) == NULL) ||
	    (!get_obj_obj(obj1, "v6AssignMode", &obj3)) ||
	    ((v6am = clone_obj(obj3)) == NULL) ||
	    (!get_obj_bool(obj1, "private", &prv))) {
		free_obj(obj1);
		free_obj(routes);
		free_obj(v4am);
		free_obj(v6am);
		send_err(w, E_BADJSON, NULL);
		return;
	}

	if (((obj2 = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj2, "id", id)) ||
	    (!add_obj_string(obj2, "name", name)) ||
	    (!add_obj_number(obj2, "creationTime", crtime)) ||
	    (!add_obj_bool(obj2, "private", prv)) ||
	    (!add_obj_int(obj2, "multicastLimit", mclim)) ||
	    (!add_obj_bool(obj2, "enableBroadcast", eb)) ||
	    (!add_obj_obj(obj2, "routes", routes))) {
		goto err;
	}
	routes = NULL;
	if (!add_obj_obj(obj2, "v4AssignMode", v4am)) {
		goto err;
	}
	v4am = NULL;
	if (!add_obj_obj(obj2, "v6AssignMode", v6am)) {
		goto err;
	}

	send_result(w, obj2);
	free_obj(obj1);
	return;
err:
	free_obj(obj1);
	free_obj(obj2);
	free_obj(routes);
	free_obj(v4am);
	free_obj(v6am);
	send_err(w, E_NOMEM, NULL);
}

static void
zt1_get_network(controller *cp, worker *w, uint64_t nwid)
{
	if (!zt1_init_req(cp, w, "/controller/network/%016llx", nwid)) {
		return;
	}

	worker_http(w, zt1_get_network_cb);
}

static void
zt1_delete_network_cb(worker *w, void *body, size_t len)
{
	object *obj;

	// Delete has no body text.
	if ((obj = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
	} else {
		send_result(w, obj);
	}
}

static void
zt1_delete_network(controller *cp, worker *w, uint64_t nwid)
{
	nng_http_req *req;

	if (!zt1_init_req(cp, w, "/controller/network/%016llx",
	        nwid)) {
		return;
	}
	req = worker_http_req(w);
	if (nng_http_req_set_method(req, "DELETE") != 0) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, zt1_delete_network_cb);
}


static void
zt1_get_members_cb(worker *w, void *body, size_t len)
{
	object *obj;
	object *arr;
	char *  name;

	if ((obj = parse_obj(body, len)) == NULL) {
		send_err(w, E_BADJSON, NULL);
		return;
	}

	if ((arr = alloc_arr()) == NULL) {
		free_obj(obj);
		send_err(w, E_NOMEM, NULL);
		return;
	}
	name = NULL;
	while ((name = next_obj_key(obj, name)) != NULL) {
		if (!add_arr_string(arr, name)) {
			free_obj(arr);
			free_obj(obj);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}
	free_obj(obj);

	send_result(w, arr);
}

static void
zt1_get_members(controller *cp, worker *w, uint64_t nwid)
{
	if (!zt1_init_req(cp, w, "/controller/network/%016llx/member", nwid)) {
		return;
	}

	worker_http(w, zt1_get_members_cb);
}

static void
zt1_get_own_members_cb(worker *w, void *body, size_t len)
{
	object  *obj;
	object  *arr;
	char *   name;
	char *   ep;
	uint64_t memid;

	if ((obj = parse_obj(body, len)) == NULL) {
		send_err(w, E_BADJSON, NULL);
		return;
	}

	if ((arr = alloc_arr()) == NULL) {
		free_obj(obj);
		send_err(w, E_NOMEM, NULL);
		return;
	}
	name = NULL;
	while (((name = next_obj_key(obj, name)) != NULL) &&
	    ((memid = strtoull(name, NULL, 16)) != 0) &&
	    (is_user_member_owner(w, memid))) {
		if (!add_arr_string(arr, name)) {
			free_obj(arr);
			free_obj(obj);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}
	free_obj(obj);

	send_result(w, arr);
}

static void
zt1_get_own_members(controller *cp, worker *w, uint64_t nwid)
{
	if (!zt1_init_req(cp, w, "/controller/network/%016llx/member", nwid)) {
		return;
	}

	worker_http(w, zt1_get_own_members_cb);
}

static void
zt1_get_member_cb(worker *w, void *body, size_t len)
{
	object *obj1;
	object *obj2;
	object *obj3;
	char *  name;
	char *  id;
	char *  nwid;
	bool    bridge;
	bool    auth;
	int     rev;
	int     vMajor;
	int     vMinor;
	int     vRev;
	int     vProto;
	object *ipassign = NULL;

	if (((obj1 = parse_obj(body, len)) == NULL) ||
	    (!get_obj_string(obj1, "id", &id)) ||
	    (!get_obj_string(obj1, "nwid", &nwid)) ||
	    (!get_obj_bool(obj1, "authorized", &auth)) ||
	    (!get_obj_int(obj1, "revision", &rev)) ||
	    (!get_obj_int(obj1, "vMajor", &vMajor)) ||
	    (!get_obj_int(obj1, "vMinor", &vMinor)) ||
	    (!get_obj_int(obj1, "vRev", &vRev)) ||
	    (!get_obj_int(obj1, "vProto", &vProto)) ||
	    (!get_obj_obj(obj1, "ipAssignments", &obj3)) ||
	    ((ipassign = clone_obj(obj3)) == NULL) ||
	    (!get_obj_bool(obj1, "activeBridge", &bridge))) {
		free_obj(obj1);
		free_obj(ipassign);
		send_err(w, E_BADJSON, NULL);
		return;
	}

	if (((obj2 = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj2, "id", id)) ||
	    (!add_obj_string(obj2, "network", nwid)) ||
	    (!add_obj_bool(obj2, "authorized", auth)) ||
	    (!add_obj_bool(obj2, "activeBridge", bridge)) ||
	    (!add_obj_int(obj2, "revision", rev)) ||
	    (!add_obj_int(obj2, "vMajor", vMajor)) ||
	    (!add_obj_int(obj2, "vMinor", vMinor)) ||
	    (!add_obj_int(obj2, "vRev", vRev)) ||
	    (!add_obj_int(obj2, "vProto", vProto)) ||
	    (!add_obj_obj(obj2, "ipAssignments", ipassign))) {
		free_obj(obj1);
		free_obj(obj2);
		free_obj(ipassign);
		send_err(w, E_NOMEM, NULL);
		return;
	}
	send_result(w, obj2);
	free_obj(obj1);
}

static void
zt1_get_member(controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	if (!zt1_init_req(cp, w, "/controller/network/%016llx/member/%010llx",
	        nwid, node)) {
		return;
	}

	worker_http(w, zt1_get_member_cb);
}

static void
zt1_delete_member_cb(worker *w, void *body, size_t len)
{
	object *obj;

	// Delete has no body text.
	// NB: As of this writing, the controller responds with a 200
	// error code, and does not actually delete the member.  We are
	// going to pretend it worked for now, and when the upstream bug
	// is fixed this code will Just Work.  Short of performing another
	// GET to see if it worked, there isn't much else we can do anyway.
	if ((obj = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
	} else {
		send_result(w, obj);
	}
}

static void
zt1_delete_member(controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	nng_http_req *req;

	if (!zt1_init_req(cp, w, "/controller/network/%016llx/member/%010llx",
	        nwid, node)) {
		return;
	}
	req = worker_http_req(w);
	if (nng_http_req_set_method(req, "DELETE") != 0) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, zt1_delete_member_cb);
}

static void
zt1_authorize_member_cb(worker *w, void *body, size_t len)
{
	object *obj;
	bool    auth;

	if (((obj = parse_obj(body, len)) == NULL) ||
	    (!get_obj_bool(obj, "authorized", &auth))) {
		free_obj(obj);
		send_err(w, E_BADJSON, NULL);
		return;
	}
	free_obj(obj);
	if (!auth) {
		send_err(w, E_INTERNAL, "Member not authorized");
		return;
	}

	if ((obj = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
	} else {
		send_result(w, obj);
	}
}

static void
zt1_authorize_member(controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	nng_http_req *req;
	char *        body = "{ \"authorized\": true }";

	if (!zt1_init_req(cp, w, "/controller/network/%016llx/member/%010llx",
	        nwid, node)) {
		return;
	}
	req = worker_http_req(w);
	if ((nng_http_req_set_method(req, "POST") != 0) ||
	    (nng_http_req_copy_data(req, body, strlen(body)) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, zt1_authorize_member_cb);
}

static void
zt1_deauthorize_member_cb(worker *w, void *body, size_t len)
{
	object *obj;
	bool    auth;

	if (((obj = parse_obj(body, len)) == NULL) ||
	    (!get_obj_bool(obj, "authorized", &auth))) {
		free_obj(obj);
		send_err(w, E_BADJSON, NULL);
		return;
	}
	free_obj(obj);
	if (auth) {
		send_err(w, E_INTERNAL, "Member still authorized");
		return;
	}

	if ((obj = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
	} else {
		send_result(w, obj);
	}
}

static void
zt1_deauthorize_member(controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	nng_http_req *req;
	char *        body = "{ \"authorized\": false }";

	if (!zt1_init_req(cp, w, "/controller/network/%016llx/member/%010llx",
	        nwid, node)) {
		return;
	}
	req = worker_http_req(w);
	if ((nng_http_req_set_method(req, "POST") != 0) ||
	    (nng_http_req_copy_data(req, body, strlen(body)) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, zt1_deauthorize_member_cb);
}

static struct {
	const char *method;
	void (*func)(controller *, worker *, object *);
} jsonrpc_methods_ctr[] = {
	{ NULL, NULL },
};

static void
zt1_exec_jsonrpc(controller *cp, worker *w, const char *meth, object *params)
{
	for (int i = 0; jsonrpc_methods_ctr[i].method != NULL; i++) {
		if (strcmp(jsonrpc_methods_ctr[i].method, meth) == 0) {
			jsonrpc_methods_ctr[i].func(cp, w, params);
			return;
		}
	}
	send_err(w, E_BADMETHOD, NULL);
}

static bool
zt1_setup(worker_config *wc, controller *cp, char **errmsg)
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
	return (true);
}

static void
zt1_teardown(controller *cp)
{
	free(cp->host);
	if (cp->client) {
		nng_http_client_free(cp->client);
	}
}

worker_ops controller_zt1_ops = {
	.version            = WORKER_OPS_VERSION,
	.type               = "zt1",
	.setup              = zt1_setup,
	.teardown           = zt1_teardown,
	.exec_jsonrpc       = zt1_exec_jsonrpc,
	.get_status         = zt1_get_status,
	.create_network     = zt1_create_network,
	.get_networks       = zt1_get_networks,
	.get_network        = zt1_get_network,
	.delete_network     = zt1_delete_network,
	.get_members        = zt1_get_members,
	.get_own_members    = zt1_get_own_members,
	.get_member         = zt1_get_member,
	.delete_member      = zt1_delete_member,
	.authorize_member   = zt1_authorize_member,
	.deauthorize_member = zt1_deauthorize_member,
};
