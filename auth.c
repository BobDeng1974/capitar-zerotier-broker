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
	object * json;
	char *   id;
	char *   desc;
	user *   user;
	uint64_t tag; // check to make sure user tag matches
	uint64_t roles;
	double   expire;
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

static bool
check_password(const char *pass, const char *hash)
{
	mbedtls_sha1_context ctx;
	unsigned char        out[20];

	if ((hash[0] == '\0') && (pass[0] == '\0')) {
		return (true);
	}

	// If the password is written as type 0, remainder is
	// the password in cleartext.  Not ideal, but easy for
	// simplistic start up passwords.
	if ((strncmp(hash, "0:", 2)) == 0) {
		if (strcmp(pass, hash + 2) == 0) {
			return (true);
		}
		return (false);
	}
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
	free_obj(u->json);
	free(u->otpwds);
	free(u);
}

static bool
parse_user(user *u)
{
	object *o = u->json;
	object *a;

	if ((!get_obj_string(o, "name", &u->name)) ||
	    (!get_obj_uint64(o, "tag", &u->tag)) ||
	    (!get_obj_string(o, "passwd", &u->encpass))) {
		return (false);
	}
	u->locked = false;
	get_obj_bool(o, "locked", &u->locked);

	// Load the user roles.  If any named roles are not found,
	// they are ignored.  This leaves us with more security by default.
	if (get_obj_obj(o, "roles", &a)) {
		char *s;
		for (int i = 0; i < get_arr_len(a); i++) {
			if (get_arr_string(a, i, &s)) {
				u->roles |= find_role(s);
			}
		}
	}

	u->notpwds = 0;
	if (get_obj_obj(o, "otpwds", &a)) {
		u->notpwds = get_arr_len(a);
		if ((u->otpwds = calloc(u->notpwds, sizeof(otpwd))) == NULL) {
			return (false);
		}

		for (int i = 0; i < u->notpwds; i++) {
			object *t;
			otpwd * otp = &u->otpwds[i];
			if ((!get_arr_obj(a, i, &t)) ||
			    (!get_obj_string(t, "name", &otp->name)) ||
			    (!get_obj_string(t, "secret", &otp->secret)) ||
			    (!get_obj_string(t, "type", &otp->type))) {
				free_user(u);
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

	return (true);
}

user *
dup_user(const user *u)
{
	user *dup;

	if (((dup = calloc(1, sizeof(user))) == NULL) ||
	    ((dup->json = clone_obj(u->json)) == NULL) || (!parse_user(dup))) {
		free_user(dup);
		return (NULL);
	}
	return (dup);
}

user *
find_user(const char *name)
{
	char *path;
	user *u;

	if ((wc == NULL) || (wc->userdir == NULL)) {
		return (NULL);
	}
	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(name)) ||
	    ((path = path_join(wc->userdir, name, ".usr")) == NULL)) {
		return (NULL);
	}
	if (((u = calloc(1, sizeof(user))) == NULL) ||
	    ((u->json = obj_load(path, NULL)) == NULL) || (!parse_user(u)) ||
	    (strcmp(u->name, name) != 0)) {
		free(path);
		free_user(u);
		return (NULL);
	}
	free(path);

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

bool
user_tokens(const user *u, token ***tokensp, int *ntokensp)
{
	token **    tokens;
	void *      dirh;
	int         nalloc;
	int         ntokens;
	char        id[128];
	const char *fname;
	int         code;

	nalloc  = 0;
	ntokens = 0;
	tokens  = NULL;

	if ((dirh = path_opendir(wc->tokendir)) == NULL) {
		if (dirh == NULL) {
			// Treat as if no tokens;
			*ntokensp = 0;
			*tokensp  = NULL;
			return (true);
		}
	}

	while ((fname = path_readdir(dirh)) != NULL) {
		size_t l;
		token *tok;
		snprintf(id, sizeof(id), "%s", fname);
		if (((l = strlen(id)) < 4) &&
		    (strcmp(&id[l - 4], ".tok") != 0)) {
			continue;
		}
		id[l - 4] = 0;
		if ((tok = find_token(id, &code, false)) == NULL) {
			continue;
		}
		if (!token_belongs(tok, u)) {
			free_token(tok);
			continue;
		}
		while (nalloc <= ntokens) {
			token **newtoks;
			// Most users won't have more than several tokens
			// around.
			nalloc  = nalloc ? (nalloc * 2) : 8;
			newtoks = realloc(tokens, nalloc * sizeof(token *));
			if (newtoks == NULL) {
				free(tokens);
				path_closedir(dirh);
				return (false);
			}
			tokens = newtoks;
		}
		tokens[ntokens++] = tok;
	}
	path_closedir(dirh);
	*ntokensp = ntokens;
	*tokensp  = tokens;
	return (true);
}

void
free_tokens(token **tokens, int ntokens)
{
	for (int i = 0; i < ntokens; i++) {
		free_token(tokens[i]);
	}
	free(tokens);
}

void
free_token(token *tok)
{
	if (tok != NULL) {
		free_user(tok->user);
		free(tok->json);
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

static bool
parse_token(token *t)
{
	char *  s;
	object *o = t->json;
	object *a;

	if (t->user != NULL) {
		free_user(t->user);
	}

	if ((!get_obj_string(o, "id", &t->id)) ||
	    (!get_obj_string(o, "user", &s)) ||
	    ((t->user = find_user(s)) == NULL) ||
	    (!get_obj_string(o, "desc", &t->desc)) ||
	    (!get_obj_uint64(o, "tag", &t->tag)) ||
	    (!get_obj_obj(o, "roles", &a))) {
		return (false);
	}
	for (int i = 0; i < get_arr_len(a); i++) {
		if (get_arr_string(a, i, &s)) {
			t->roles |= find_role(s);
		}
	}
	get_obj_number(o, "expire", &t->expire);
	// Mask off any roles the user doesn't have.
	t->roles &= t->user->roles;

	// The tag must match the original user, the user must not be locked,
	// and the token should not have expired.
	if ((t->tag != t->user->tag) || t->user->locked) {
		return (false);
	}

	return (true);
}

token *
find_token(const char *id, int *code, bool validate)
{
	char * path;
	token *t;

	if ((wc == NULL) || (wc->tokendir == NULL)) {
		*code = E_AUTHTOKEN;
		return (NULL);
	}
	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(id)) ||
	    ((path = path_join(wc->tokendir, id, ".tok")) == NULL)) {
		*code = E_AUTHTOKEN;
		return (NULL);
	}
	if ((t = calloc(1, sizeof(token))) == NULL) {
		free(path);
		*code = E_NOMEM;
		return (NULL);
	}
	if ((t->json = obj_load(path, NULL)) == NULL) {
		*code = E_AUTHTOKEN;
		free(path);
		free_token(t);
		return (NULL);
	}
	free(path);
	if ((!parse_token(t)) || (strcmp(t->id, id) != 0)) {
		// This is a bad token, so purge it.  This happens if
		// the user does not match, for example.
		*code = E_AUTHTOKEN;
		delete_token(t);
		return (NULL);
	}

	if (validate && ((t->expire != 0) && (t->expire < time(NULL)))) {
		*code = E_AUTHEXPIRE;
		free_token(t);
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
create_token(user *u, const char *desc, double expire, uint64_t roles)
{
	token * t;
	char *  path;
	object *a;
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

	// mask off roles the user object lacks
	roles &= u->roles;

	if (((t = calloc(1, sizeof(token))) == NULL) ||
	    ((t->json = alloc_obj()) == NULL) ||
	    (!add_obj_string(t->json, "id", idbuf)) ||
	    (!add_obj_string(t->json, "user", u->name)) ||
	    (!add_obj_string(t->json, "desc", desc)) ||
	    (!add_obj_uint64(t->json, "tag", u->tag)) ||
	    (!add_obj_number(t->json, "expire", expire))) {
		free_token(t);
		return (NULL);
	}
	if ((a = alloc_arr()) == NULL) {
		free_token(t);
		return (NULL);
	}
	for (int i = 0; i < wc->nroles; i++) {
		if ((wc->roles[i].mask & roles) == 0) {
			continue;
		}
		if (!add_arr_string(a, wc->roles[i].name)) {
			free_token(t);
			free_obj(a);
			return (NULL);
		}
	}
	if (!add_obj_obj(t->json, "roles", a)) {
		free_obj(a);
		free_token(t);
		return (NULL);
	}
	if (!parse_token(t)) {
		free_token(t);
		return (NULL);
	}

	if ((path = path_join(wc->tokendir, t->id, ".tok")) == NULL) {
		free_token(t);
		return (NULL);
	}
	if (!obj_save(path, t->json, NULL)) {
		free(path);
		free_token(t);
		return (NULL);
	}

	free(path);
	return (t);
}

const char *
token_id(const token *tok)
{
	return (tok->id);
}

const char *
token_desc(const token *tok)
{
	return (tok->desc);
}

bool
token_belongs(const token *tok, const user *u)
{
	if ((strcmp(tok->user->name, u->name) == 0) && (tok->tag == u->tag)) {
		return (true);
	}
	return (false);
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

bool
check_api_role(const char *method, uint64_t roles)
{
	// XXX: We need to add API authorization checks.
	(void) method;
	(void) roles;
	return (true);
}

bool
check_nwid_role(uint64_t nwid, uint64_t roles)
{
	// XXX: We need to add NWID authorization checks.
	(void) nwid;
	(void) roles;
	return (true);
}

void
auth_init(worker_config *cfg)
{
	wc = cfg;
}
