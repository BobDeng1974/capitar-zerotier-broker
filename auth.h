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

#ifndef AUTH_H
#define AUTH_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "object.h"
#include "worker.h"

typedef struct otpwd otpwd; // one time password
typedef struct token token; // authentication (bearer) token
typedef struct user  user;

// auth_init must be called with a valid configuration at the
// start of operations, or nothing else will work.
extern void auth_init(worker_config *);

extern uint64_t    user_roles(const user *);
extern const char *user_name(const user *);
extern void        free_user(user *);
extern user *      dup_user(const user *);
extern user *      find_user(const char *);
extern user *auth_user(const char *name, const char *, const char *, int *);
extern void  delete_user(user *);

extern void        free_token(token *);
extern uint64_t    token_roles(const token *);
extern const user *token_user(const token *);
extern token *     find_token(const char *, int *);
extern void        delete_token(token *);
extern token *     create_token(user *, const char *, time_t, uint64_t);

extern uint64_t    find_role(const char *);
extern uint64_t    find_role_ext(worker_config *, const char *);
extern const char *role_name(uint64_t);

#endif
