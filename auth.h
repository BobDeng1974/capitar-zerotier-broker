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

#include "object.h"
#include "worker.h"

typedef struct otpwd otpwd; // one time password
typedef struct token token; // authentication (bearer) token
typedef struct user user;

struct token {
	object * json;
	char *   id;
	char *   desc;
	user *   user;
	uint64_t tag; // check to make sure user tag matches
	uint64_t roles;
	double   expire;
	double   created;
};

struct otpwd {
	char *   name;
	char *   secret;  // base32, should be 32 digits (160 bits)
	char *   type;    // "totp" or "hotp" -- only "totp" for now
	int      digits;  // 6, 7, 8 (only 6 supported for now)
	int      period;  // for totp
	uint64_t counter; // for hotp
};

struct user {
	object * json;
	char *   name;
	char *   encpass;
	uint64_t tag;    // random tag prevents reuse
	bool     locked; // true if account is locked
	uint64_t roles;
	int      notpwds;
	otpwd *  otpwds;
};

// auth_init must be called with a valid configuration at the
// start of operations, or nothing else will work.
extern void auth_init(worker_config *);

extern uint64_t    user_roles(const user *);
extern const char *user_name(const user *);
extern void        free_user(user *);
extern user *      dup_user(const user *);
extern user *      find_user(const char *);
extern user *      auth_user(const char *name, const char *, const char *, int *);
extern user *      create_user(object *, int *);
extern void        delete_user(user *);
extern object *    user_names();
extern bool        set_password(user *, const char *);
extern bool        create_totp(user *, const char *);
extern bool        delete_totp(user *);

extern int          user_num_otpwds(const user *);
extern const otpwd *user_otpwd(const user *, int);
extern const char * otpwd_name(const otpwd *);
extern const char * otpwd_secret(const otpwd *);
extern const char * otpwd_type(const otpwd *);
extern int          otpwd_digits(const otpwd *);
extern int          otpwd_period(const otpwd *);

extern void        free_token(token *);
extern uint64_t    token_roles(const token *);
extern const user *token_user(const token *);
extern token *     find_token(const char *, int *, bool);
extern void        delete_token(token *);
extern token *     create_token(user *, const char *, double, uint64_t);
extern const char *token_id(const token *);
extern const char *token_desc(const token *);
extern bool        token_belongs(const token *, const user *);
extern double      token_created(const token *);
extern double      token_expires(const token *);
extern bool        token_has_expired(const token *);
extern bool        user_tokens(const user *, token ***, int *);
extern void        free_tokens(token **, int);
extern void        purge_expired_tokens();

extern uint64_t    find_role(const char *);
extern uint64_t    find_role_ext(worker_config *, const char *);
extern const char *role_name(uint64_t);
extern bool        check_api_role(const char *, uint64_t);
extern bool        check_nwid_role(uint64_t, uint64_t);

#define ROLE_ADMIN (1ULL << 63) // %admin - implicitly can do everything
#define ROLE_TOKEN (1ULL << 62) // %token - applies to users using API token
#define ROLE_ALL (1ULL << 61)   // %all - applies to everyone
#endif
