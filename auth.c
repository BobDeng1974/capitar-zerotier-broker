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
#include <time.h>
#include <string.h>

#include <mbedtls/sha1.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "auth.h"
#include "base32.h"
#include "config.h"
#include "otp.h"
#include "util.h"
#include "worker.h"
#include "controller.h"

static worker_config *wc;


char *
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
	char *name1;

	if ((wc == NULL) || (wc->userdir == NULL)) {
		return (NULL);
	}

	// ensure name is lower case, so name auth can be case insensitive
	name1 = strdup(name);
	to_lower(name1);

	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(name1)) ||
	    ((path = path_join(wc->userdir, name1, ".usr")) == NULL)) {
		free(name1);
		return (NULL);
	}
	if (((u = calloc(1, sizeof(user))) == NULL) ||
	    ((u->json = obj_load(path, NULL)) == NULL) || (!parse_user(u)) ||
	    (strcmp(u->name, name1) != 0)) {
		free(path);
		free_user(u);
		free(name1);
		return (NULL);
	}
	free(path);
	free(name1);

	return (u);
}

int
user_num_otpwds(const user *u)
{
	return (u->notpwds);
}

const otpwd *
user_otpwd(const user *u, int idx)
{
	if ((idx >= 0) && (idx < u->notpwds)) {
		return (&u->otpwds[idx]);
	}
	return (NULL);
}

const char *
otpwd_name(const otpwd *o)
{
	return (o->name);
}

const char *
otpwd_secret(const otpwd *o)
{
	return (o->secret);
}

const char *
otpwd_type(const otpwd *o)
{
	return (o->type);
}

int
otpwd_digits(const otpwd *o)
{
	return (o->digits);
}
int
otpwd_period(const otpwd *o)
{
	return (o->period);
}

bool
set_password(user *u, const char *pass)
{
	char *  enc;
	char *  enc2;
	char *  path;
	object *obj;

	if ((enc = hash_password(pass)) == NULL) {
		return (false);
	}
	if (((obj = clone_obj(u->json)) == NULL) ||
	    (!add_obj_string(obj, "passwd", enc)) ||
	    (!get_obj_string(obj, "passwd", &enc2))) {
		free(enc);
		free_obj(obj);
		return (false);
	}
	free(enc);
	if ((path = path_join(wc->userdir, u->name, ".usr")) == NULL) {
		free(enc2);
		free_obj(obj);
		return (false);
	}

	if (!obj_save(path, obj, NULL)) {
		free(path);
		free_obj(obj);
		return (false);
	}

	free(path);
	free_obj(u->json);
	u->json = obj;
	return (true);
}

// create_totp creates a one time password entry.
// At the moment, this service only supports a single TOTP secret
// at a time, so if you have multiple devices you will need to
// enter the same secret on all of them.  This will erase any
// previously configured OTP entries.
bool
create_totp(user *u, const char *name)
{
	object *obj;
	object *old;
	object *arr;
	char *  path;
	char    encbuf[33];
	uint8_t secret[20];
	size_t  len;

	for (int i = 0; i < sizeof(secret); i += sizeof(uint32_t)) {
		uint32_t r = nng_random();
		memcpy(&secret[i], &r, sizeof(r));
	}
	len = base32_encode(secret, sizeof(secret), encbuf, sizeof(encbuf));
	if (len >= sizeof(encbuf)) {
		return (false); // base32 buffer overrun?  Should never happen.
	}
	// Note that the values for digits and period are required for the
	// Google authenticator.
	if (((obj = alloc_obj()) == NULL) ||
	    (!add_obj_string(obj, "name", name)) ||
	    (!add_obj_string(obj, "type", "totp")) ||
	    (!add_obj_string(obj, "secret", encbuf)) ||
	    (!add_obj_number(obj, "period", 30)) ||
	    (!add_obj_number(obj, "digits", 6))) {
		free_obj(obj);
		return (false);
	}
	if (((arr = alloc_arr()) == NULL) || (!add_arr_obj(arr, obj)) ||
	    ((obj = clone_obj(u->json)) == NULL) ||
	    (!add_obj_obj(obj, "otpwds", arr))) {
		free_obj(arr);
		free_obj(obj);
		return (false);
	}

	// Save the generated token...
	if ((path = path_join(wc->userdir, u->name, ".usr")) == NULL) {
		free_obj(obj);
		return (false);
	}
	if (!obj_save(path, obj, NULL)) {
		free(path);
		free_obj(obj);
		return (false);
	}

	// The file change is in effect.  Let's reparse.
	// Note that if something bad happens here, the user might
	// well be unusable. Best bet is for the caller to free the
	// user and start over.  Note also that the change to the OTP
	// will have taken effect.  This could leave the user locked
	// locked out.
	free(u->otpwds);
	u->otpwds  = NULL;
	u->notpwds = 0;
	old        = u->json;
	u->json    = obj;
	if (!parse_user(u)) {
		u->json = old;
		free(obj);
		return (false);
	}
	free(old);
	return (true);
}

bool
delete_totp(user *u)
{
	object *obj = NULL;
	object *arr;
	char *  path;

	if (((arr = alloc_arr()) == NULL) ||
	    (!add_obj_obj(u->json, "otpwds", arr))) {
		free_obj(arr);
		return (false);
	}

	free(u->otpwds);
	u->otpwds  = NULL;
	u->notpwds = 0;

	// Save the generated token...
	if ((path = path_join(wc->userdir, u->name, ".usr")) == NULL) {
		return (false);
	}
	if (!obj_save(path, u->json, NULL)) {
		free(path);
		return (false);
	}

	return (true);
}

static bool
check_otp(const user *u, const char *pin)
{
	// This code rather naively checks each 2FA.  We don't have
	// support for HOTP as we don't want to store and update
	// counters in the database.  TOTP is stateless.
	uint64_t now = time(NULL);

	for (int i = 0; i < u->notpwds; i++) {
		otpwd *  op;
		char     otpbuf[16]; // digits should 6, 7, 8 or 9
		uint8_t  decbuf[32]; // overkill - techically 20 is sufficient
		size_t   declen;
		uint64_t period;

		op = &u->otpwds[i];
		// No support for HOTP for now.
		if (strcmp(op->type, "totp") != 0) {
			continue;
		}
		// Base32 decode of the secret.  The secret should
		// be 160 bits long.  That corresponds to 20 bytes
		// of output, and 32 bytes of hash.   32 bytes of output
		// would allow for a 256 bit key for the future.
		declen = base32_decode(
		    op->secret, strlen(op->secret), decbuf, sizeof(decbuf));
		if ((declen == 0) || (declen > sizeof(decbuf))) {
			continue; // bad decode
		}
		// Default is 30s.
		period = op->period != 0 ? op->period : 30;

		// We will run the OTP twice.  Once for the last period,
		// and once for the current period.  This allows us to use
		// a password even if the interval was just crossed.
		otp(otpbuf, sizeof(otpbuf), decbuf, declen, op->digits,
		    (now / period) - 1);
		if (strcmp(otpbuf, pin) == 0) {
			return (true);
		}
		otp(otpbuf, sizeof(otpbuf), decbuf, declen, op->digits,
		    (now / period));
		if (strcmp(otpbuf, pin) == 0) {
			return (true);
		}
	}
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

user *
create_user(object *newuser, int *code)
{
	char *path;
	user *u;
	char *name;
	char *name1;

	if ((wc == NULL) || (wc->userdir == NULL)) {
		return (NULL);
	}

	if ((!get_obj_string(newuser, "name", &name)) ||
	    (empty(name))) {
		*code = E_BADPARAMS;
		return (NULL);
	}

	// ensure name is lower case, so name auth can be case insensitive
	name1 = strdup(name);
	to_lower(name1);

	if ((!add_obj_string(newuser, "name", name1)) ||
	    (!add_obj_uint64(newuser, "created_ms", nng_clock()))) {
		*code = E_NOMEM;
		return (NULL);
	}

	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(name1)) ||
	    ((path = path_join(wc->userdir, name1, ".usr")) == NULL)) {
		*code = E_BADPARAMS;
		return (NULL);
	}
	if (path_exists(path)) {
		*code = E_EXISTS;
		return (NULL);
	}

	if (!obj_save(path, newuser, NULL)) {
		*code = E_INTERNAL;
		free_obj(newuser);
		free(path);
		return (NULL);
	}
	free_obj(newuser);

	if (((u = calloc(1, sizeof(user))) == NULL) ||
	    ((u->json = obj_load(path, NULL)) == NULL) || (!parse_user(u)) ||
	    (strcmp(u->name, name1) != 0)) {
		free(path);
		free_user(u);
		return (NULL);
	}
	free(path);

	return (u);
}

bool
save_user(user *u, int *code)
{
	char *path;
	char *name;

	if ((wc == NULL) || (wc->userdir == NULL)) {
		return (false);
	}

	if ((!get_obj_string(u->json, "name", &name)) ||
	    (strcmp(u->name, name) != 0)) {
		*code = E_BADPARAMS;
		return (false);
	}
	if (!add_obj_uint64(u->json, "updated_ms", nng_clock())) {
		*code = E_NOMEM;
		return (false);
	}
	// Sanity check here to ensure name is safe for files.
	if ((!safe_filename(name)) ||
	    ((path = path_join(wc->userdir, name, ".usr")) == NULL)) {
		*code = E_BADPARAMS;
		return (false);
	}

	if (!obj_save(path, u->json, NULL)) {
		*code = E_INTERNAL;
		free(path);
		return (false);
	}

	free(path);

	return (true);
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

object *
user_names()
{

	void *       dirh;
	object *     names;
	const char * fname;
	char        id[128];

	if (((wc == NULL) ||
	    ((dirh = path_opendir(wc->userdir)) == NULL))) {
		if (dirh == NULL) {
			return (NULL);
		}
	}

	names = alloc_arr();

	while ((fname = path_readdir(dirh)) != NULL) {
		snprintf(id, sizeof(id), "%s", fname);
		// Only return items ending with .usr
		size_t l;
		if (((l = strlen(id)) << 4) &&
		    (strcmp(&id[l - 4], ".usr") != 0)) {
			continue;
		}
		id[l - 4] = 0;
		add_arr_string(names, id);
	}
	path_closedir(dirh);
	return (names);
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
	get_obj_number(o, "create", &t->created);
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
	    (!add_obj_number(t->json, "create", (double) time(NULL))) ||
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
	// If present in user role, %admin role may also be assigned to the token
	if ((roles & ROLE_ADMIN) != 0) {
	        if (!add_arr_string(a, role_name(ROLE_ADMIN))) {
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

double
token_expires(const token *tok)
{
	return (tok->expire);
}

double
token_created(const token *tok)
{
	return (tok->created);
}

bool
token_has_expired(const token *tok)
{
	if ((tok->expire != 0) && (tok->expire < time(NULL))) {
		return true;
	}
	return false;
}

bool
token_belongs(const token *tok, const user *u)
{
	if ((strcmp(tok->user->name, u->name) == 0) && (tok->tag == u->tag)) {
		return (true);
	}
	return (false);
}

void
purge_expired_tokens(void *notused)
{
	(void) notused;
	const char *fname;
	int         code;
	void *      dirh;
	char        id[128];


	if ((wc == NULL) || (wc->tokendir == NULL)) {
		return;
	}

	if (wc->debug) {
		printf("purge_expired_tokens()\n");
	}

	if ((dirh = path_opendir(wc->tokendir)) == NULL) {
		if (dirh == NULL) {
			return;
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
		if (token_has_expired(tok)) {
			if (wc->debug) {
				printf("deleting expired token %s\n", print_obj(tok->json));
			}
			delete_token(tok);
		} else {
			free_token(tok);
		}

		// Go easy on system
		nng_msleep(100);
	}
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

// Returns the bit associated with a role name.  Looks up rolegroups
// as well. Returns 0 if nothing matches.
uint64_t
find_role_ext(worker_config *c, const char *role)
{
	if (role[0] == '%') {
		if (strcmp(role, "%admin") == 0) {
			return (ROLE_ADMIN);
		}
		if (strcmp(role, "%token") == 0) {
			return (ROLE_TOKEN);
		}
		if (strcmp(role, "%all") == 0) {
			return (ROLE_ALL);
		}
		return (0);
	}
	for (int i = 0; i < c->nroles; i++) {
		if (strcmp(c->roles[i].name, role) == 0) {
			return (c->roles[i].mask);
		}
	}
	for (int i = 0; i < c->nrolegrps; i++) {
		if (strcmp(c->rolegrps[i].name, role) == 0) {
			return (c->rolegrps[i].mask);
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
	switch (role) {
	case ROLE_ADMIN:
		return "%admin";
	case ROLE_TOKEN:
		return "%token";
	case ROLE_ALL:
		return "%all";
	}
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
	uint64_t allow = 0;
	uint64_t deny  = 0;

	if ((roles & ROLE_ADMIN) != 0) {
		// admin can do everything
		return (true);
	}
	for (int i = 0; i < wc->napis; i++) {
		if (strcmp(wc->apis[i].method, method) == 0) {
			allow = wc->apis[i].allow;
			deny  = wc->apis[i].deny;
			break;
		}
		if (strcmp(wc->apis[i].method, "*") == 0) {
			// wild card match, but keep searching
			allow = wc->apis[i].allow;
			deny  = wc->apis[i].deny;
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

bool
check_nwid_role(uint64_t nwid, uint64_t roles)
{
	uint64_t allow = 0;
	uint64_t deny  = 0;

	if ((roles & ROLE_ADMIN) != 0) {
		return (true);
	}
	for (int i = 0; i < wc->nnets; i++) {
		if (wc->nets[i].nwid == nwid) {
			allow = wc->nets[i].allow;
			deny  = wc->nets[i].deny;
			break;
		}
		if (wc->nets[i].nwid == 0) {
			allow = wc->nets[i].allow;
			deny  = wc->nets[i].deny;
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

bool
check_controller_role(controller *cp, uint64_t roles)
{

	if ((roles & ROLE_ADMIN) != 0) {
		if (cp->debug > 1) {
			printf("controller_role %s user ROLE_ADMIN\n", cp->config->name);
		}
		return (true);
	}

	if ((roles & cp->config->allow) != 0) {
		if (cp->debug > 1) {
			printf("controller_role %s allow\n", cp->config->name);
		}
		return (true);
	}
	if ((roles & cp->config->deny) != 0) {
		if (cp->debug > 1) {
			printf("controller_role %s deny\n", cp->config->name);
		}
		return (false);
	}

	// For unauthenticated requests (without token)
	if ((cp->config->allow & ROLE_ALL) != 0) {
		if (cp->debug > 1) {
			printf("controller_role %s allow ROLE_ALL\n", cp->config->name);
		}
		return (true);
	}
	if ((cp->config->deny & ROLE_ALL) != 0) {
		if (cp->debug > 1) {
			printf("controller_role %s deny ROLE_ALL\n", cp->config->name);
		}
		return (false);
	}

	// default is permissive
	if (cp->debug > 1) {
		printf("controller_role %s default permissive\n", cp->config->name);
	}
	return (true);
}

void
auth_init(worker_config *cfg)
{
	wc = cfg;
}
