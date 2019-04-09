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


extern nng_tls_config *tls;
extern worker_ops *    find_worker_ops(const char *);

int debug;


static bool
central_init_req(controller *cp, worker *w, const char *fmt, ...)
{
	char          uri[256];
	char          token[256];
	nng_http_req *req;
	va_list       ap;

	req = worker_http_req(w);
	nng_http_req_reset(req);

	va_start(ap, fmt);
	vsnprintf(uri, sizeof(uri), fmt, ap);
	va_end(ap);

	snprintf(token, sizeof(token), "Bearer %s", get_controller_secret(cp));

	if ((nng_http_req_set_uri(req, uri) != 0) ||
	    (nng_http_req_set_header(req, "Host", get_controller_host(cp)) !=
	        0) ||
	    (nng_http_req_set_header(req, "Authorization", token) != 0) ||
	    (nng_http_req_set_data(req, NULL, 0) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return (false);
	}
	return (true);
}

static void
central_get_status_cb(worker *w, void *body, size_t len)
{
	object *obj;
	bool    b;

	if (((obj = parse_obj(body, len)) == NULL) ||
	    (!get_obj_bool(obj, "online", &b)) || (!b)) {
		free_obj(obj);
		send_err(w, E_BADJSON, NULL);
		return;
	}
	free_obj(obj);
	if (((obj = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj, "version", RPC_VERSION)) ||
	    (!add_obj_bool(obj, "controller", false)) ||
	    (!add_obj_bool(obj, "central", true))) {
		free_obj(obj);
		send_err(w, E_NOMEM, NULL);
		return;
	}

	send_result(w, obj);
}

static void
central_get_status(controller *cp, worker *w)
{
	if (!central_init_req(cp, w, "/api/status")) {
		return;
	}
	worker_http(w, central_get_status_cb);
}

static void
central_get_networks_cb(worker *w, void *body, size_t len)
{
	object *arr;
	object *arr2;

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
		object * obj;
		char *   s;
		char *   ep;
		uint64_t nwid;
		if ((!get_arr_obj(arr, i, &obj)) ||
		    (!get_obj_string(obj, "id", &s)) ||
		    ((nwid = strtoull(s, &ep, 16)) == 0) || (*ep != '\0')) {
			free_obj(arr);
			free_obj(arr2);
			send_err(w, E_BADJSON, NULL);
			return;
		}
		if (!nwid_allowed(nwid)) {
			continue;
		}
		if (!add_arr_string(arr2, s)) {
			free_obj(arr);
			free_obj(arr2);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}
	free_obj(arr);
	send_result(w, arr2);
}

static void
central_get_networks(controller *cp, worker *w)
{
	if (!central_init_req(cp, w, "/api/network")) {
		return;
	}

	worker_http(w, central_get_networks_cb);
}

static void
central_get_network_cb(worker *w, void *body, size_t len)
{
	object *obj0;
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

	//printf("get_network_cb %s\n", (char *) body);

	if (((obj0 = parse_obj(body, len)) == NULL) ||
	    (!get_obj_obj(obj0, "config", &obj1)) ||
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
		if (debug) {
			printf("get_network_cb badjson %s\n", (char *) body);
		}
		free_obj(obj0);
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

	free_obj(obj0);
	send_result(w, obj2);
	return;
err:
	free_obj(obj0);
	free_obj(obj2);
	free_obj(routes);
	free_obj(v4am);
	free_obj(v6am);
	send_err(w, E_NOMEM, NULL);
}

static void
central_get_network(controller *cp, worker *w, uint64_t nwid)
{
	if (!central_init_req(cp, w, "/api/network/%016llx", nwid)) {
		return;
	}

	worker_http(w, central_get_network_cb);
}

static void
central_get_members_cb(worker *w, void *body, size_t len)
{
	object *arr1;
	object *arr2;

	if ((arr1 = parse_obj(body, len)) == NULL) {
		send_err(w, E_BADJSON, NULL);
		return;
	}

	if ((arr2 = alloc_arr()) == NULL) {
		free_obj(arr1);
		send_err(w, E_NOMEM, NULL);
		return;
	}
	for (int i = 0; i < get_arr_len(arr1); i++) {
		object *obj;
		char *  s;
		if ((!get_arr_obj(arr1, i, &obj)) ||
		    (!get_obj_string(obj, "nodeId", &s))) {
			free_obj(arr2);
			free_obj(arr1);
			send_err(w, E_BADJSON, NULL);
			return;
		}
		if (!add_arr_string(arr2, s)) {
			free_obj(arr2);
			free_obj(arr1);
			send_err(w, E_NOMEM, NULL);
			return;
		}
	}
	free_obj(arr1);

	send_result(w, arr2);
}

static void
central_get_members(controller *cp, worker *w, uint64_t nwid)
{
	if (!central_init_req(cp, w, "/api/network/%016llx/member", nwid)) {
		return;
	}

	worker_http(w, central_get_members_cb);
}

static void
central_get_member_cb(worker *w, void *body, size_t len)
{
	object *obj0;
	object *obj1;
	object *obj2;
	object *obj3;
	char *  name;
	char *  id;
	char *  nwid;
	bool    bridge;
	bool    auth;
	int     rev;
	object *ipassign = NULL;

	if (((obj0 = parse_obj(body, len)) == NULL) ||
	    (!get_obj_obj(obj0, "config", &obj1)) ||
	    (!get_obj_string(obj1, "id", &id)) ||
	    (!get_obj_string(obj1, "nwid", &nwid)) ||
	    (!get_obj_bool(obj1, "authorized", &auth)) ||
	    (!get_obj_int(obj1, "revision", &rev)) ||
	    (!get_obj_obj(obj1, "ipAssignments", &obj3)) ||
	    ((ipassign = clone_obj(obj3)) == NULL) ||
	    (!get_obj_bool(obj1, "activeBridge", &bridge))) {
		free_obj(obj0);
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
	    (!add_obj_obj(obj2, "ipAssignments", ipassign))) {
		free_obj(obj0);
		free_obj(obj2);
		free_obj(ipassign);
		send_err(w, E_NOMEM, NULL);
		return;
	}

	send_result(w, obj2);
	free_obj(obj0);
}

static void
central_get_member(controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	if (!central_init_req(
	        cp, w, "/api/network/%016llx/member/%010llx", nwid, node)) {
		return;
	}

	worker_http(w, central_get_member_cb);
}

static void
central_delete_member(controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	// Feel free to fix this when/if Central adds DELETE support.

	send_err(w, E_INTERNAL, "Central does not support DELETE of members");
}

static void
central_authorize_member_cb(worker *w, void *body, size_t len)
{
	object *obj1;
	object *obj2;
	bool    auth;

	if (((obj1 = parse_obj(body, len)) == NULL) ||
	    (!get_obj_obj(obj1, "config", &obj2)) ||
	    (!get_obj_bool(obj2, "authorized", &auth))) {
		free_obj(obj1);
		send_err(w, E_BADJSON, NULL);
		return;
	}
	free_obj(obj1);
	if (!auth) {
		send_err(w, E_INTERNAL, "Member not authorized");
		return;
	}

	if ((obj1 = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
	} else {
		send_result(w, obj1);
	}
}

static void
central_authorize_member(
    controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	nng_http_req *req;
	char *        body = "{ \"config\": { \"authorized\": true }}";

	if (!central_init_req(
	        cp, w, "/api/network/%016llx/member/%010llx", nwid, node)) {
		return;
	}

	req = worker_http_req(w);
	if ((nng_http_req_set_method(req, "POST") != 0) ||
	    (nng_http_req_copy_data(req, body, strlen(body)) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, central_authorize_member_cb);
}

static void
central_deauthorize_member_cb(worker *w, void *body, size_t len)
{
	object *obj1;
	object *obj2;
	bool    auth;

	if (((obj1 = parse_obj(body, len)) == NULL) ||
	    (!get_obj_obj(obj1, "config", &obj2)) ||
	    (!get_obj_bool(obj2, "authorized", &auth))) {
		free_obj(obj1);
		send_err(w, E_BADJSON, NULL);
		return;
	}
	free_obj(obj1);
	if (auth) {
		send_err(w, E_INTERNAL, "Member still authorized");
		return;
	}

	if ((obj1 = alloc_obj()) == NULL) {
		send_err(w, E_NOMEM, NULL);
	} else {
		send_result(w, obj1);
	}
}

static void
central_deauthorize_member(
    controller *cp, worker *w, uint64_t nwid, uint64_t node)
{
	nng_http_req *req;
	char *        body = "{ \"config\": { \"authorized\": false }}";

	if (!central_init_req(
	        cp, w, "/api/network/%016llx/member/%010llx", nwid, node)) {
		return;
	}

	req = worker_http_req(w);
	if ((nng_http_req_set_method(req, "POST") != 0) ||
	    (nng_http_req_copy_data(req, body, strlen(body)) != 0)) {
		send_err(w, E_NOMEM, NULL);
		return;
	}
	worker_http(w, central_deauthorize_member_cb);
}

static struct {
	const char *method;
	void (*func)(controller *, worker *, object *);
} jsonrpc_methods_ctr[] = {
	{ NULL, NULL },
};

static void
central_exec_jsonrpc(
    controller *cp, worker *w, const char *meth, object *params)
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
ztcentral_setup(worker_config *wc, controller *cp, char **errmsg)
{
	int      rv;
	nng_url *url = NULL;

	debug = wc->debug;

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
ztcentral_teardown(controller *cp)
{
	free(cp->host);
	if (cp->client != NULL) {
		nng_http_client_free(cp->client);
	}
}

worker_ops controller_ztcentral_ops = {
	.version            = WORKER_OPS_VERSION,
	.type               = "ztcentral",
	.setup              = ztcentral_setup,
	.teardown           = ztcentral_teardown,
	.exec_jsonrpc       = central_exec_jsonrpc,
	.get_status         = central_get_status,
	.get_networks       = central_get_networks,
	.get_network        = central_get_network,
	.get_members        = central_get_members,
	.get_member         = central_get_member,
	.delete_member      = central_delete_member,
	.authorize_member   = central_authorize_member,
	.deauthorize_member = central_deauthorize_member,
};
