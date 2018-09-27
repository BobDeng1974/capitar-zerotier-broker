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

#include <ctype.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/sha1.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "auth.h"
#include "config.h"
#include "util.h"

static worker_config *wc;

struct otpwd {
	char *   name;
	char *   secret;  // this may need to change to binary format
	char *   type;    // "totp" or "hotp" -- only "totp" for now
	int      digits;  // 6, 7, 8 (only 6 supported for now)
	int      period;  // for totp
	uint64_t counter; // for hotp
};

struct token {
	char *   id;
	char *   desc;
	user *   user;
	uint64_t tag; // check to make sure user tag matches
	uint64_t roles;
	double   expire;
};

struct user {
	char *   name;
	char *   encpass;
	uint64_t tag;    // random tag prevents reuse
	bool     locked; // true if account is locked
	uint64_t roles;
	int      notpwds;
	otpwd *  otpwds;
};

static bool
check_password(const char *pass, const char *hash)
{
	mbedtls_sha1_context ctx;
	unsigned char        out[20];

	if ((strncmp(hash, "1:", 2) != 0) && (strlen(hash) != 51)) {
		return (false);
	}
	mbedtls_sha1_init(&ctx);
	mbedtls_sha1_update_ret(&ctx, (void *) hash, 11);
	mbedtls_sha1_update_ret(&ctx, (void *) pass, strlen(pass));
	mbedtls_sha1_finish_ret(&ctx, out);
	mbedtls_sha1_free(&ctx);
	hash += 11;

	for (int i = 0; i < 20; i++) {
		char buf[3];
		snprintf(buf, 3, "%02x", out[i]);
		if (memcmp(buf, hash, 2) != 0) {
			return (false);
		}
		hash += 2;
	}
	return (true);
}

uint64_t
user_roles(const user *u)
{
	return (u->roles);
}

const char *
user_name(const user *u)
{
	return (u->name);
}

void
free_user(user *u)
{
	if (u == NULL) {
		return;
	}
	free(u->name);
	free(u->encpass);
	free(u->otpwds);
	free(u);
}

user *
dup_user(const user *u)
{
	user *dup;

	if (((dup = calloc(1, sizeof(user))) == NULL) ||
	    ((dup->name = strdup(u->name)) == NULL) ||
	    ((dup->encpass = strdup(u->encpass)) == NULL) ||
	    ((dup->otpwds = calloc(u->notpwds, sizeof(otpwd))) == NULL)) {
		free_user(dup);
		return (NULL);
	}
	for (int i = 0; i < dup->notpwds; i++) {
		otpwd *sp = &u->otpwds[i];
		otpwd *dp = &u->otpwds[i];
		if (((dp->secret = strdup(sp->secret)) == NULL) ||
		    ((dp->name = strdup(sp->name)) == NULL) ||
		    ((dp->type = strdup(sp->type)) == NULL)) {
			free_user(dup);
			return (NULL);
		}
		dp->digits  = sp->digits;
		dp->counter = sp->counter;
		dp->period  = sp->period;
	}
	dup->roles   = u->roles;
	dup->tag     = u->tag;
	dup->notpwds = u->notpwds;
	return (dup);
}

user *
find_user(const char *name)
{
	char *  path;
	int     i;
	user *  u;
	char *  str;
	bool    b;
	object *obj;
	object *arr;

	if ((wc == NULL) || (wc->userdir == NULL)) {
		return (NULL);
	}
	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(name)) ||
	    ((path = path_join(wc->userdir, name, ".usr")) == NULL)) {
		return (NULL);
	}
	obj = obj_load(path, NULL);
	free(path);
	if (obj == NULL) {
		return (NULL);
	}
	if ((u = calloc(1, sizeof(user))) == NULL) {
		free_obj(obj);
		return (NULL);
	}
	if ((!get_obj_uint64(obj, "tag", &u->tag)) ||
	    ((u->name = strdup(name)) == NULL) ||
	    (!get_obj_string(obj, "password", &str)) ||
	    ((u->encpass = strdup(str)) == NULL)) {
		free_obj(obj);
		free_user(u);
		return (NULL);
	}

	get_obj_bool(obj, "locked", &u->locked);

	// Load the user roles.  If any named roles are not found,
	// they are ignored.  This leaves us with more security by default.
	if (get_obj_obj(obj, "roles", &arr)) {
		for (int i = 0; i < get_arr_len(arr); i++) {
			if (get_arr_string(arr, i, &str)) {
				u->roles |= find_role(str);
			}
		}
	}

	if (get_obj_obj(obj, "tokens", &arr)) {
		u->notpwds = get_arr_len(arr);
		if ((u->otpwds = calloc(u->notpwds, sizeof(otpwd))) == NULL) {
			free_user(u);
			free_obj(obj);
			return (NULL);
		}

		for (int i = 0; i < u->notpwds; i++) {
			object *t;
			otpwd * otp = &u->otpwds[i];
			if ((!get_arr_obj(arr, i, &t)) ||
			    (!get_obj_string(t, "name", &str)) ||
			    ((otp->name = strdup(str)) == NULL) ||
			    (!get_obj_string(t, "secret", &str)) ||
			    ((otp->secret = strdup(str)) == NULL) ||
			    (!get_obj_string(t, "type", &str)) ||
			    ((otp->type = strdup(str)) == NULL)) {
				free_user(u);
				free_obj(obj);
				return (NULL);
			}
			otp->period  = 30;
			otp->digits  = 6;
			otp->counter = 0;
			// Allow overrides.
			(void) get_obj_int(t, "digits", &otp->digits);
			(void) get_obj_int(t, "period", &otp->period);
			(void) get_obj_uint64(t, "counter", &otp->counter);
		}
	}

	// We could add additional attributes here -- last login, expiration,
	// password security settings, etc. etc.
	return (u);
}

static bool
check_otp(const user *u, const char *otp)
{
	// Add validation of OTP here.
	// For now we are returning false.
	return (false);
}

user *
auth_user(const char *name, const char *pass, const char *otp, int *code)
{
	user *u;

	if ((u = find_user(name)) == NULL) {
		*code = E_AUTHFAIL;
		return (NULL);
	}
	if ((u->locked) || (!check_password(pass, u->encpass))) {
		*code = E_AUTHFAIL;
		free_user(u);
		return (NULL);
	}
	// If the user has 2FA configured, then we refuse to let them in.
	if (u->notpwds > 0) {
		if (otp == NULL) {
			*code = E_AUTHOTP;
			free_user(u);
			return (NULL);
		} else if (!check_otp(u, otp)) {
			*code = E_AUTHFAIL;
			free_user(u);
			return (NULL);
		}
	}
	return (u);
}

void
delete_user(user *u)
{
	char *path;

	// Arguably we should go through and find all token files that
	// are owned by the user and delete them.  My kingdom for a SQL
	// database.  We use random tags on user records and correlate
	// them with tokens to prevent accidental reuse.
	if ((path = path_join(wc->userdir, u->name, ".usr")) == NULL) {
		return;
	}
	path_delete(path);
	free(path);
	free_user(u);
}

void
free_token(token *tok)
{
	if (tok != NULL) {
		free_user(tok->user);
		free(tok);
	}
}

uint64_t
token_roles(const token *tok)
{
	return (tok->roles);
}

const user *
token_user(const token *tok)
{
	return (tok->user);
}

token *
find_token(const char *id)
{
	char *  path;
	int     i;
	user *  u;
	char *  str;
	bool    b;
	token * t;
	object *obj;
	object *arr;

	if ((wc == NULL) || (wc->tokendir == NULL)) {
		return (NULL);
	}
	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(id)) ||
	    ((path = path_join(wc->tokendir, id, ".tok")) == NULL)) {
		return (NULL);
	}
	obj = obj_load(path, NULL);
	free(path);
	if (obj == NULL) {
		return (NULL);
	}
	if (((t = calloc(1, sizeof(token))) == NULL) ||
	    ((t->id = strdup(id)) == NULL) ||
	    (!get_obj_string(obj, "id", &str)) || (strcmp(t->id, str) != 0) ||
	    (!get_obj_string(obj, "user", &str)) ||
	    ((t->user = find_user(str)) == NULL) ||
	    (!get_obj_uint64(obj, "tag", &t->tag)) ||
	    (t->tag != t->user->tag) || (!get_obj_obj(obj, "roles", &arr))) {
		free_token(t);
		free_obj(obj);
		return (NULL);
	}
	for (int i = 0; i < get_arr_len(arr); i++) {
		if (get_arr_string(arr, i, &str)) {
			t->roles |= find_role(str);
		}
	}
	// Mask off any roles the user doesn't have.
	t->roles &= t->user->roles;

	if (t->user->locked) {
		// Maybe we should delete the token as well?
		free_token(t);
		free_obj(obj);
		return (NULL);
	}

	if (t->user->tag != t->tag) {
		// Stale token from an earlier version of this user,
		// delete it.
		delete_token(t);
		free_obj(obj);
		return (NULL);
	}

	if (get_obj_number(obj, "expire", &t->expire) &&
	    (t->expire < time(NULL))) {
		// its already expired, or its the wrong user.
		free_obj(obj);
		delete_token(t);
		return (NULL);
	}

	return (t);
}

void
delete_token(token *t)
{
	char *path;

	if ((path = path_join(wc->tokendir, t->id, ".tok")) == NULL) {
		return;
	}
	path_delete(path);
	free(path);
	free_token(t);
}

token *
create_token(user *u, const char *desc, time_t expire, uint64_t roles)
{
	token * t;
	char *  path;
	object *obj;
	object *arr;
	char    idbuf[64];

	// 192 bit token, plenty of entropy, 48 hex characters.  Base 64 would
	// be 16-bits smaller, but this works.
	snprintf(idbuf, sizeof(idbuf), "%08x%08x%08x%08x%08x%08x",
	    nng_random(), nng_random(), nng_random(), nng_random(),
	    nng_random(), nng_random());

	if ((wc == NULL) || (wc->tokendir == NULL)) {
		return (NULL);
	}
	if (desc == NULL) {
		desc = "";
	}
	if (expire && (expire < time(NULL))) {
		return (NULL);
	}
	if ((t = calloc(1, sizeof(token))) == NULL) {
		return (NULL);
	}
	t->expire = expire;
	t->tag    = u->tag;
	if (((t->id = strdup(idbuf)) == NULL) ||
	    ((t->user = dup_user(u)) == NULL) ||
	    ((t->desc = strdup(desc)) == NULL)) {
		free_token(t);
		return (NULL);
	}
	if ((arr = alloc_arr()) == NULL) {
		for (int i = 0; i < wc->nroles; i++) {
			if ((wc->roles[i].mask & t->roles) == 0) {
				continue;
			}
			if (!add_arr_string(arr, wc->roles[i].name)) {
				free_token(t);
				free_obj(arr);
				return (NULL);
			}
		}
	}
	if (((obj = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj, "id", t->id)) ||
	    (!add_obj_string(obj, "desc", t->desc)) ||
	    (!add_obj_string(obj, "user", t->user->name)) ||
	    (!add_obj_uint64(obj, "tag", t->tag)) ||
	    (!add_obj_number(obj, "expire", t->expire)) ||
	    (!add_obj_obj(obj, "roles", arr))) {
		free_obj(obj);
		free_obj(arr);
		free_token(t);
		return (NULL);
	}

	if ((path = path_join(wc->tokendir, t->id, ".tok")) == NULL) {
		free_obj(obj);
		free_token(t);
		return (NULL);
	}
	if (!obj_save(path, obj, NULL)) {
		free(path);
		free_obj(obj);
		free_token(t);
		return (NULL);
	}
	free(path);
	free_obj(obj);
	return (t);
}

// Authentication support.  This code is meant for the worker,
// and has the necessary backing support for all of our authentication
// primitives.

// Authentication database is structured as a directory, with several
// subdirectories.

// authdb/users - contains a list of user files (username.json)
// authdb/tokens - contains a list of token files
//
// (These might be come from the master config file?)
// authdb/roles.json - contains a list of roles
// authdb/methods.json - contains a list of method/role filters
// authdb/networks.json - contains a list of network/role filters

// set_auth_db sets the database location for authentication.

// hash password hashes the password into the given result using a
// random salt, and and returns a string.  This string will be
// NULL terminated and should be freed when no longer needed.
// Note that the algorithm used is *not* designed to burn lots of
// CPU, so the resulting string should still be treated with the
// same care as the original password.  Hashing it is just designed
// to guard against accidental casual exposure to the administrator.

static char *
hash_password(const char *pass)
{
	mbedtls_sha1_context ctx;
	char *               result;
	unsigned char        hash[20];
	char *               ptr;

	// The salt is "1:<8 random hex digits>:".  The 1: means
	// we are using SHA1.  4 billion is enough salts for us.
	// "1:%08x:" is 11 bytes (not including terminator).
	if ((result = malloc(11 + 40 + 1)) == NULL) {
		return (NULL);
	}
	snprintf(result, 12, "1:%08x:", nng_random());

	mbedtls_sha1_init(&ctx);
	mbedtls_sha1_update_ret(&ctx, (void *) result, 11);
	mbedtls_sha1_update_ret(&ctx, (void *) pass, strlen(pass));
	mbedtls_sha1_finish_ret(&ctx, hash);
	mbedtls_sha1_free(&ctx);

	ptr = result + strlen(result);
	for (int i = 0; i < 20; i++) {
		snprintf(ptr, 3, "%02x", hash[i]);
		ptr += 2;
	}
	return (result);
}

// Returns the bit associated with a role name.
uint64_t
find_role_ext(worker_config *c, const char *role)
{
	for (int i = 0; i < c->nroles; i++) {
		if (strcmp(c->roles[i].name, role) == 0) {
			return (c->roles[i].mask);
		}
	}
	return (0);
}

uint64_t
find_role(const char *role)
{
	return (find_role_ext(wc, role));
}

const char *
role_name(uint64_t role)
{
	for (int i = 0; i < wc->nroles; i++) {
		if (wc->roles[i].mask == role) {
			return (wc->roles[i].name);
		}
	}
	return (NULL);
}

void
auth_init(worker_config *cfg)
{
	wc = cfg;
}
