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

#ifndef ENTITY_ROLES_H
#define ENTITY_ROLES_H


#include "object.h"

typedef struct entity_roles_config entity_roles_config;
typedef struct role_config role_config;
typedef struct rolegrp_config rolegrp_config;
typedef struct action_config action_config;
typedef struct worker worker;

// This macro makes us do asprintf conditionally.
#define ERRF(strp, fmt, ...) \
        if (strp != NULL)    \
        asprintf(strp, fmt, ##__VA_ARGS__)

struct role_config {
	char *   name;
	uint64_t mask;
};

struct rolegrp_config {
	char *   name;
	uint64_t mask;
};

struct action_config {
	char *   action;
	uint64_t allow; // mask of allowed roles
	uint64_t deny;  // mask of denied roles
};

// An entity_roles_config has the JSON tree associated with it and references
// that.  The configuration is destroyed at the same time the tree is.
struct entity_roles_config {
	object *           json;         // JSON for the entire tree
	int                nroles;       // Number of roles (permissions)
	role_config *      roles;        // Role (name & bit)
	int                nrolegrps;    // Number of role groups
	rolegrp_config *   rolegrps;     // Role group (name & mask)
	int                nactions;     // Number of apis / actions in entity
	action_config *    actions;      // Actions that can be used / on the entity (invite etc.)
};

extern void free_entity_roles_config(entity_roles_config *);
extern bool parse_entity_roles(entity_roles_config *, object *, uint64_t *, char **);
extern bool valid_entity_rolename(const char *);
extern uint64_t find_entity_role(entity_roles_config *, const char *);
extern uint64_t user_entity_roles(entity_roles_config *, char *, uint64_t);
extern uint64_t eff_entity_roles(entity_roles_config *, worker *);
extern bool check_entity_role_action(entity_roles_config *, worker *, char *);
extern entity_roles_config * load_entity_roles_config(const char *, char **, int);

#endif // ENTITY_ROLES_H
