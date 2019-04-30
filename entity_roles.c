//
// Copyright 2019 Capitar IT Group BV <info@capitar.com>
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


#include <nng/nng.h>

#include "entity_roles.h"
#include "auth.h"
#include "object.h"
#include "util.h"

#include <ctype.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

int debug;


void
free_entity_roles_config(entity_roles_config *erc)
{
	if (erc != NULL) {
		free_obj(erc->json);
		free(erc->roles);
		free(erc->actions);
		free(erc);
	}
}

bool
parse_entity_roles(entity_roles_config *erc, object *arr, uint64_t *maskp, char **errmsg)
{
	uint64_t m = 0;
	uint64_t v;
	char *   n;
	for (int i = 0; i < get_arr_len(arr); i++) {
		if (!get_arr_string(arr, i, &n)) {
			ERRF(errmsg, "bad role array item at index %d", i);
			return (false);
		}
		if ((v = find_entity_role(erc, n)) == 0) {
			ERRF(errmsg, "unknown role %s", n);
			return (false);
		}

		m |= v;
	}
	*maskp = m;
	return (true);
}

bool
valid_entity_rolename(const char *name)
{
	if ((name == NULL) || ((!isalnum(name[0])) && (name[0] != '_'))) {
		return (false);
	}
	for (int j = 0; j < name[j] != '\0'; j++) {
		if (!isprint(name[j])) {
			return (false);
		}
	}
	return (true);
}

uint64_t
find_entity_role(entity_roles_config *erc, const char *role)
{
	if (role[0] == '%') {
		// Return default from auth
		return find_role(role);
	}
	for (int i = 0; i < erc->nroles; i++) {
		if (strcmp(erc->roles[i].name, role) == 0) {
			return (erc->roles[i].mask);
		}
	}
	for (int i = 0; i < erc->nrolegrps; i++) {
		if (strcmp(erc->rolegrps[i].name, role) == 0) {
			return (erc->rolegrps[i].mask);
		}
	}
	// Return default from auth
	return find_role(role);
}

uint64_t user_entity_roles(entity_roles_config *erc, char *username, uint64_t usertag) {
	uint64_t  roles = 0;
	object   *obj1;
	uint64_t tag;

	if ((!get_obj_obj(erc->json, "users", &obj1)) ||
	    (!get_obj_uint64(obj1, "tag", &tag)) ||
	    (tag != usertag) ||
	    (!get_obj_obj(obj1, "roles", &obj1))) {
		return (roles);
	}

	char *s;
	for (int i = 0; i < get_arr_len(obj1); i++) {
		if (get_arr_string(obj1, i, &s)) {
			roles |= find_role(s);
		}
	}
	return (roles);
}

uint64_t eff_entity_roles(entity_roles_config *erc, worker *w) {
	uint64_t roles = w->eff_roles;
	roles |= user_entity_roles(erc, w->username, w->usertag);
	// User roles can be subtraced by proxy rules.
	roles &= ~w->proxy->config->role_del;
	return (roles);
}

bool check_entity_role_action(entity_roles_config *erc, worker *w, char *action) {
	uint64_t allow = 0;
	uint64_t deny  = 0;

	uint64_t roles = eff_entity_roles(erc, w);

	if ((roles & ROLE_ADMIN) != 0) {
		// admin can do everything
		return (true);
	}
	for (int i = 0; i < erc->nactions; i++) {
		if (strcmp(erc->actions[i].action, action) == 0) {
			allow = erc->actions[i].allow;
			deny  = erc->actions[i].deny;
			break;
		}
		if (action[0] == "_"[0]) {
			// No wild card for actions starting with _
			deny = ROLE_ALL;
			continue;
		}
		if (strcmp(erc->actions[i].action, "*") == 0) {
			// wild card match, but keep searching
			allow = erc->actions[i].allow;
			deny  = erc->actions[i].deny;
		}
	}
	if ((roles & allow) != 0) {
		return (true);
	}
	if ((roles & deny) != 0) {
		return (false);
	}

	// For unauthenticated requests (without token)
	if ((allow & ROLE_ALL) != 0) {
		return (true);
	}
	if ((deny & ROLE_ALL) != 0) {
		return (false);
	}

	// default is permissive
	return (true);
}

entity_roles_config *
load_entity_roles_config(const char *path, char **errmsg, int nroles)
{
	object              *obj;
	object              *arr;
	entity_roles_config *erc;

	if ((erc = calloc(1, sizeof(worker_config))) == NULL) {
		ERRF(errmsg, "calloc: %s", strerror(errno));
		return (NULL);
	}
	if ((erc->json = obj_load(path, errmsg, debug)) == NULL) {
		goto error;
	}

	erc->nroles = 0;
	if (get_obj_obj(erc->json, "roles", &arr)) {
		int n;
		if (!is_obj_array(arr)) {
			ERRF(errmsg, "roles must be array");
			goto error;
		}

		// For now we are only permitting 32 roles.  The reason
		// is so that we can reserve up to 32 additional built-in
		// roles which are not configuration file driven.
		if ((n = get_arr_len(arr)) > 32) {
			ERRF(errmsg, "too many roles");
			goto error;
		}
		if ((n > 0) &&
		    ((erc->roles = calloc(sizeof(role_config), n)) == NULL)) {
			ERRF(errmsg, "calloc: %s", strerror(errno));
			goto error;
		}
		for (erc->nroles = 0; erc->nroles < n; erc->nroles++) {
			int          idx = erc->nroles;
			role_config *r   = &erc->roles[idx];
			if (!get_arr_string(arr, idx, &r->name)) {
				ERRF(errmsg, "role %d: not a string", idx);
				goto error;
			}
			// Role names are required to start with an alpha
			// numeric or [_].  They furthermore must consist
			// entirely of printable characters.  Special role
			// names used by the system will start with other
			// characters.
			if (!valid_entity_rolename(r->name)) {
				ERRF(errmsg, "role %d: invalid name", idx);
				goto error;
			}
			if (find_entity_role(erc, r->name) != 0) {
				ERRF(errmsg, "role %d: duplicate name", idx);
				goto error;
			}
			if (nroles + erc->nroles > 32) {
				ERRF(errmsg, "Exceding maximum of 32 roles");
				goto error;
			}
			r->mask = 1U << (nroles + erc->nroles);
			if (debug > 1) {
				printf("ROLE %s: mask %llx\n", r->name,
				    (unsigned long long) r->mask);
			}
		}
	}

	// Load role groups.  Role groups are named like roles, but
	// use a group name to refer to multiple other roles.  The
	// values are prefixed by an @ sign.  As a little bonus,
	// rolegroups can reference other rolegroups, provided that the
	// referent is listed before the referrer.
	erc->nrolegrps = 0;
	if (get_obj_obj(erc->json, "rolegroups", &arr)) {
		int     n;
		object *rarr;
		if (!is_obj_array(arr)) {
			ERRF(errmsg, "rolegroups must be array");
			goto error;
		}

		n = get_arr_len(arr);
		if ((n > 0) &&
		    ((erc->rolegrps = calloc(sizeof(role_config), n)) ==
		        NULL)) {
			ERRF(errmsg, "calloc: %s", strerror(errno));
			goto error;
		}

		for (erc->nrolegrps = 0; erc->nrolegrps < n; erc->nrolegrps++) {
			object *        robj;
			object *        rarr;
			int             idx = erc->nrolegrps;
			rolegrp_config *r   = &erc->rolegrps[idx];

			if (!get_arr_obj(arr, erc->nrolegrps, &robj)) {
				ERRF(errmsg, "rolegroup %d: not object", idx);
				free_entity_roles_config(erc);
				return (NULL);
			}
			if (!get_obj_string(robj, "name", &r->name)) {
				ERRF(
				    errmsg, "rolegroup %d: missing name", idx);
				free_entity_roles_config(erc);
				return (NULL);
			}
			if (!valid_entity_rolename(r->name)) {
				ERRF(
				    errmsg, "rolegroup %d: invalid name", idx);
				free_entity_roles_config(erc);
				return (NULL);
			}
			if (find_entity_role(erc, r->name) != 0) {
				ERRF(errmsg, "rolegroup %d: duplicate name",
				    idx);
				free_entity_roles_config(erc);
				return (NULL);
			}
			if ((!get_obj_obj(robj, "roles", &rarr)) ||
			    (!is_obj_array(rarr))) {
				ERRF(errmsg, "rolegroup %d: bad roles", idx);
				goto error;
			}
			if (!parse_entity_roles(erc, rarr, &r->mask, errmsg)) {
				goto error;
			}
			if (debug > 1) {
				printf("ROLEGRP %s: mask %llx\n", r->name,
				    (unsigned long long) r->mask);
			}
		}
	}

	erc->nactions = 0;
	if (get_obj_obj(erc->json, "action", &arr)) {
		char *key;
		int   i;
		for (key = next_obj_key(arr, NULL); key != NULL;
		     key = next_obj_key(arr, key)) {
			erc->nactions++;
		}
		if ((erc->actions = calloc(sizeof(action_config), erc->nactions)) ==
		    NULL) {
			ERRF(errmsg, "calloc: %s", strerror(errno));
			goto error;
		}
		for (key = next_obj_key(arr, NULL), i = 0; key != NULL;
		     key = next_obj_key(arr, key), i++) {
			object *ao;
			object *roles;
			bool    valid;

			if (!get_obj_obj(arr, key, &ao)) {
				ERRF(errmsg, "action %d: not an object", i);
				goto error;
			}
			erc->actions[i].action = key;
			erc->actions[i].allow  = 0;
			erc->actions[i].deny   = 0;

			if ((get_obj_obj(ao, "allow", &roles)) &&
			    (!parse_entity_roles(
			        erc, roles, &erc->actions[i].allow, errmsg))) {
				goto error;
			}
			if ((get_obj_obj(ao, "deny", &roles)) &&
			    (!parse_entity_roles(
			        erc, roles, &erc->actions[i].deny, errmsg))) {
				goto error;
			}
			for (int j = 0; j < i; j++) {
				if (strcmp(erc->actions[j].action, key) == 0) {
					ERRF(errmsg, "action %d: duplicate", i);
					goto error;
				}
			}
		}
	}

error:
	free_entity_roles_config(erc);
	return (NULL);
}
