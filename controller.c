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

// controller methods

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/http/http.h>

#include "object.h"
#include "worker.h"
#include "controller.h"
#include "auth.h"
#include "util.h"


bool
get_auth_param_with_session(worker *w, object *params, user **userp) {
	user      *u;
	object    *obj1;

	if (!get_auth_param(w, params, &u)) {
		return (false);
	}
	if (!valid_worker_session(w)) {
		return (false);
	}

	add_obj_string(w->session, "username", strdup(u->name));

	if ((get_obj_obj(u->json, "networks", &obj1)) &&
	    (!add_obj_obj(w->session, "user_networks", clone_obj(obj1)))) {
		free_user(u);
		send_err(w, E_NOMEM, NULL);
		return (false);
	}

	if ((get_obj_obj(u->json, "devices", &obj1)) &&
	    (!add_obj_obj(w->session, "user_devices", clone_obj(obj1)))) {
		free_user(u);
		send_err(w, E_NOMEM, NULL);
		return (false);
	}

	if (userp != NULL) {
		*userp = u;
	} else {
		free_user(u);
	}

	return (true);
}

bool
is_user_network_owner(worker *w, uint64_t nwid)
{
	object   *ses1;
	bool      is_owner = false;
	char      str[32];

	(void) snprintf(str, sizeof(str), "%016llx", (unsigned long long) nwid);
	if ((w != NULL) &&
	    (w->session != NULL) &&
	    (get_obj_obj(w->session, "user_networks", &ses1)) &&
	    (get_obj_obj(ses1, str, &ses1)) &&
	    (get_obj_bool(ses1, "is_owner", &is_owner)) &&
	    (is_owner)) {
		return (true);
	}
}

bool
is_user_member_owner(worker *w, uint64_t memid)
{
	object   *ses1;
	bool      enrolled = false;
	char      str[32];

	(void) snprintf(str, sizeof(str), "%010llx", (unsigned long long) memid);
	if ((w != NULL) &&
	    (w->session != NULL) &&
	    (get_obj_obj(w->session, "user_devices", &ses1)) &&
	    (get_obj_obj(ses1, str, &ses1)) &&
	    (get_obj_bool(ses1, "enrolled", &enrolled)) &&
	    (enrolled)) {
		return (true);
	}
}

bool
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
	if (!check_nwid_role(nwid, w->eff_roles)) {
		// Security: Treat network denied as if it does not exist.
		send_err(w, 404, "no such network");
		return (false);
	}

	*cpp   = cp;
	*nwidp = nwid;
	return (true);
}

bool
get_own_network_param(worker *w, object *params, controller **cpp, uint64_t *nwidp)
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
	if (!is_user_network_owner(w, nwid)) {
		// Security: Treat network denied as if it does not exist.
		send_err(w, 404, "no such network");
		return (false);
	}

	*cpp   = cp;
	*nwidp = nwid;
	return (true);
}

bool
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

bool
get_own_network_member_param(worker *w, object *params, controller **cpp, uint64_t *nwidp,
    uint64_t *memidp)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    memid;

	if (!get_own_network_param(w, params, &cp, &nwid)) {
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

bool
get_own_member_param(worker *w, object *params, controller **cpp, uint64_t *nwidp,
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
	if (!is_user_member_owner(w, memid)) {
		// Security: Treat network denied as if it does not exist.
		send_err(w, 404, "no such network");
		return (false);
	}
	*cpp    = cp;
	*nwidp  = nwid;
	*memidp = memid;
	return (true);
}

void
get_status(worker *w, object *params)
{
	controller *cp;

	// NO auth check.  Should we require authentication here?

	if (get_controller_param(w, params, &cp)) {
		if (!cp->ops->get_status) {
			return;
		}
		cp->ops->get_status(cp, w);
	}
}

void
create_network(worker *w, object *params)
{
	controller *cp;
	user       *u;
	object     *nwinfo;

	if ((get_auth_param_with_session(w, params, &u)) &&
	    (get_controller_param(w, params, &cp))) {
		if (!cp->ops->create_network) {
			free_user(u);
			return;
		}
		if ((!add_obj_string(w->session, "network_creator", u->name)) ||
                   (!add_obj_uint64(w->session, "network_creator_tag", u->tag))) {
			free_user(u);
			send_err(w, E_NOMEM, NULL);
			return;
		}
		if ((get_obj_obj(params, "nwinfo", &nwinfo)) &&
		    (!add_obj_obj(w->session, "nwinfo", clone_obj(nwinfo)))) {
			free_user(u);
			send_err(w, E_NOMEM, NULL);
			return;
		}
		free_user(u);
		cp->ops->create_network(cp, w, params);
	}
}

void
get_networks(worker *w, object *params)
{
	controller *cp;

	if (get_auth_param(w, params, NULL) &&
	    get_controller_param(w, params, &cp)) {
		if (!cp->ops->get_networks) {
			return;
		}
		cp->ops->get_networks(cp, w);
	}
}

void
get_network(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param(w, params, NULL) &&
	    get_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->get_network) {
			return;
		}
		cp->ops->get_network(cp, w, nwid);
	}
}

void
delete_network_on_result(worker *w, object *result) {
	user     *u;
	char     *username;
	uint64_t nwid;
	object   *obj1;
	object   *obj2;
	char     nwid_str[32];
	int      errcode;
	object  *usernames;

	if (!get_obj_uint64(w->session, "nwid", &nwid)) {
		send_err(w, E_INTERNAL, "No nwid in session");
		return;
	}
	(void) snprintf(nwid_str, sizeof(nwid_str), "%016llx", (long long) nwid);

	// First try to delete network from session user
	if ((get_obj_string(w->session, "username", &username)) &&
	    ((u = find_user(username)) != NULL) &&
	    (get_obj_obj(u->json, "networks", &obj1)) &&
	    (del_obj_item(obj1, nwid_str))) {
		save_user(u, &errcode);
	}

	if (username != NULL) {
		free_user(u);
		username = NULL;
	}

	send_result(w, result);

	// Delete network references from all users
	usernames = user_names();
	for (int i = 0; i < get_arr_len(usernames); i++) {
		if ((get_arr_string(usernames, i, &username)) &&
		    ((u = find_user(username)) != NULL) &&
		    (get_obj_obj(u->json, "networks", &obj1)) &&
		    (get_obj_obj(obj1, nwid_str, &obj2)) &&
		    (del_obj_item(obj1, nwid_str))) {
			save_user(u, &errcode);
		}
		if (username != NULL) {
			free_user(u);
			username = NULL;
		}
	}
	free_obj(usernames);
}

void
delete_network(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if ((get_auth_param_with_session(w, params, NULL)) &&
	    get_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->delete_network) {
			return;
		}
		if (w->on_result == NULL) {
			w->on_result = delete_network_on_result;
			add_obj_uint64(w->session, "nwid", nwid);
		}
		cp->ops->delete_network(cp, w, nwid);
	}
}

void
delete_own_network(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->delete_network) {
			return;
		}
		if (w->on_result == NULL) {
			w->on_result = delete_network_on_result;
			add_obj_uint64(w->session, "nwid", nwid);
		}
		cp->ops->delete_network(cp, w, nwid);
	}
}

void
get_network_members(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param(w, params, NULL) &&
	    get_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->get_members) {
			return;
		}
		cp->ops->get_members(cp, w, nwid);
	}
}

void
get_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param(w, params, NULL) &&
	    get_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->get_member) {
			return;
		}
		cp->ops->get_member(cp, w, nwid, member);
	}
}

void
delete_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param(w, params, NULL) &&
	    get_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->delete_member) {
			return;
		}
		cp->ops->delete_member(cp, w, nwid, member);
	}
}

void
authorize_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param(w, params, NULL) &&
	    get_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->authorize_member) {
			return;
		}
		cp->ops->authorize_member(cp, w, nwid, member);
	}
}

void
deauthorize_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param(w, params, NULL) &&
	    get_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->deauthorize_member) {
			return;
		}
		cp->ops->deauthorize_member(cp, w, nwid, member);
	}
}

void
get_own_network(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->get_network) {
			return;
		}
		cp->ops->get_network(cp, w, nwid);
	}
}

void
get_own_network_members(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->get_members) {
			return;
		}
		cp->ops->get_members(cp, w, nwid);
	}
}

void
get_own_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->get_member) {
			return;
		}
		cp->ops->get_member(cp, w, nwid, member);
	}
}

void
delete_own_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->delete_member) {
			return;
		}
		cp->ops->delete_member(cp, w, nwid, member);
	}
}

void
authorize_own_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->authorize_member) {
			return;
		}
		cp->ops->authorize_member(cp, w, nwid, member);
	}
}

void
deauthorize_own_network_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_network_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->deauthorize_member) {
			return;
		}
		cp->ops->deauthorize_member(cp, w, nwid, member);
	}
}

void
get_network_own_members(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_network_param(w, params, &cp, &nwid)) {
		if (!cp->ops->get_own_members) {
			return;
		}
		cp->ops->get_own_members(cp, w, nwid);
	}
}

void
get_network_own_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->get_member) {
			return;
		}
		cp->ops->get_member(cp, w, nwid, member);
	}
}

void
delete_network_own_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->delete_member) {
			return;
		}
		cp->ops->delete_member(cp, w, nwid, member);
	}
}

void
authorize_network_own_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->authorize_member) {
			return;
		}
		cp->ops->authorize_member(cp, w, nwid, member);
	}
}

void
deauthorize_network_own_member(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;
	uint64_t    member;

	if (get_auth_param_with_session(w, params, NULL) &&
	    get_own_member_param(w, params, &cp, &nwid, &member)) {
		if (!cp->ops->deauthorize_member) {
			return;
		}
		cp->ops->deauthorize_member(cp, w, nwid, member);
	}
}

void
enroll_own_device_next2(worker *w, object *result)
{
	int       vProto;
	char     *username;
	uint64_t  tag;
	user     *u;
	object   *obj1;
	char     *network;
	char     *member;
	int       errcode;
	char     *errmsg;

	if ((!valid_worker_session(w)) ||
	    (!get_obj_obj(w->session, "params", &obj1)) ||
	    (!get_obj_string(obj1, "network", &network)) ||
	    (!get_obj_string(obj1, "member", &member))) {
		send_err(w, E_INTERNAL, "No session params");
		free_obj(result);
		return;
	}

	if ((!get_obj_int(result, "vProto", &vProto)) ||
	    (vProto == -1)) {
		ERRF(&errmsg, "Device %s has not joined the enroll network %s", member, network);
		send_err(w, E_NOTFOUND, errmsg);
		free_obj(result);
		return;
	}
	if ((u = get_worker_session_user(w)) == NULL) {
                send_err(w, E_NOTFOUND, "Cannot match session user");
		free_obj(result);
		return;
        }

	if ((!get_obj_obj(u->json, "devices", &obj1)) ||
	    (!get_obj_obj(obj1, member, &obj1)) ||
	    (!add_obj_bool(obj1, "enrolled", true))) {
		free_user(u);
		free_obj(result);
		send_err(w, 404, "No such device");
		return;
	}

	if (!save_user(u, &errcode)) {
		free_user(u);
		free_obj(result);
		send_err(w, errcode, NULL);
		return;
        }
	free_user(u);
	send_result(w, result);
}

void
enroll_own_device_next(worker *w, object *result)
{
	controller *cp;
        uint64_t  deviceId;
        uint64_t  nwid;
	object   *params;

	free_obj(result);

	if (!valid_worker_session(w)) {
		return;
	}

	if ((!get_obj_obj(w->session, "params", &params))) {
		send_err(w, E_INTERNAL, "No session params");
	}

	if (w->on_result == NULL) {
		w->on_result = enroll_own_device_next2;
	}

	if (get_own_network_member_param(w, params, &cp, &nwid, &deviceId)) {
		if (!cp->ops->get_member) {
			return;
		}
		cp->ops->get_member(cp, w, nwid, deviceId);
	}
}

void
enroll_own_device(worker *w, object *params)
{
	user *    u;
	controller *cp;
	object   *obj1;
	object   *device;
	object   *nw;
	int       errcode;
        uint64_t  deviceId;
        uint64_t  nwid;
	char      deviceIdStr[32];
	char      nwidStr[32];
	char     *nwtype;

	if (!valid_worker_session(w)) {
		return;
	}

	if (w->on_result == NULL) {
		w->on_result = enroll_own_device_next;
		add_obj_obj(w->session, "params", clone_obj(params));
	}

	if (!get_auth_param_with_session(w, params, &u)) {
		return;
	}

	if ((!get_obj_uint64(params, "member", &deviceId)) ||
	    (!get_obj_uint64(params, "network", &nwid))) {
		send_err(w, E_BADPARAMS, "Wrong parameters");
		return;
	}

	// Ensure valid format of deviceId, must have 10 characters (including leading zeros)
	(void) snprintf(deviceIdStr, sizeof(deviceIdStr), "%010llx", (unsigned long long) deviceId);

	// Ensure valid format of nwid, must have 16 characters (including leading zeros)
	(void) snprintf(nwidStr, sizeof(nwidStr), "%016llx", (unsigned long long) nwid);

	if ((!get_obj_obj(u->json, "devices", &obj1)) ||
	    (!get_obj_obj(obj1, deviceIdStr, &device))) {
		free_user(u);
		send_err(w, 404, "No such device");
		return;

	}
	if ((!get_obj_obj(u->json, "networks", &obj1)) ||
	    (!get_obj_obj(obj1, nwidStr, &nw))) {
		free_user(u);
		send_err(w, 404, "No such enroll network");
		return;
	}

	if ((!get_obj_string(nw, "type", &nwtype)) ||
	    (!samestr(nwtype, "device_enroll"))) {
		send_err(w, E_FORBIDDEN, "Not an enroll network");
		free_user(u);
		return;
	}

	if (!set_worker_session_user(w, u)) {
		send_err(w, E_NOMEM, NULL);
		free_user(u);
		return;
	}

	free_user(u);

	if (get_own_network_member_param(w, params, &cp, &nwid, &deviceId)) {
		if (!cp->ops->authorize_member) {
			return;
		}
		cp->ops->authorize_member(cp, w, nwid, deviceId);
	}

}
