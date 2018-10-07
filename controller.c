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

#include "cfgfile.h"
#include "object.h"
#include "worker.h"

struct controller {
	char *             addr;
	char *             name;
	char *             secret;
	char *             host; // for HTTP
	nng_http_client *  client;
	worker_ops *       ops;
	controller_config *config;
};

void get_status(worker *, object *);
void get_networks(worker *, object *);
void get_network(worker *, object *);
void get_network_members(worker *, object *);
void get_network_member(worker *, object *);
void delete_network_member(worker *, object *);
void authorize_network_member(worker *, object *);
void deauthorize_network_member(worker *, object *);

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
	if (!nwid_allowed(nwid)) {
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

	if (get_network_param(w, params, &cp, &nwid)) {
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

void
get_status(worker *w, object *params)
{
	controller *cp;

	// NO auth check.  Should we require authentication here?

	if (get_controller_param(w, params, &cp)) {
		cp->ops->get_status(cp, w);
	}
}

void
get_networks(worker *w, object *params)
{
	controller *cp;

	if (get_auth_param(w, params, NULL) &&
	    get_controller_param(w, params, &cp)) {
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
		cp->ops->get_network(cp, w, nwid);
	}
}

void
get_network_members(worker *w, object *params)
{
	controller *cp;
	uint64_t    nwid;

	if (get_auth_param(w, params, NULL) &&
	    get_network_param(w, params, &cp, &nwid)) {
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
		cp->ops->deauthorize_member(cp, w, nwid, member);
	}
}
