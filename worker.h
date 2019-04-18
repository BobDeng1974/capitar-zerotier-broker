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

#ifndef WORKER_H
#define WORKER_H

#include <nng/supplemental/http/http.h>

#include "object.h"
#include "rpc.h"

typedef struct worker_config worker_config;
typedef struct worker_ops    worker_ops;
typedef struct worker        worker;
typedef struct controller    controller;
typedef struct user          user;
typedef struct proxy         proxy;
typedef struct response      response;
typedef struct netperm netperm;

typedef void (*result_callback)(worker *, object *);
typedef void (*error_callback)(worker *, int, const char *);

typedef enum {
        STATE_RECVING,
        STATE_HTTPING,
        STATE_REPLYING,
        STATE_IDLE,
} worker_state;


// when authenticating a user using username/password, we return the actual
// user structure.  As we only do this for auth methods, we want the
// user structure.

extern const char *get_controller_host(controller *);
extern const char *get_controller_secret(controller *);

// send_resp sends a response object (on success).
extern void send_result(worker *, object *);

// send_err sends an error with the given status code, and reason.
extern void send_err(worker *, int, const char *);

// These functions are intended for the implementation to use when
// communicating with the HTTP backend controller or central.
extern nng_http_req *worker_http_req(worker *);
extern nng_http_res *worker_http_res(worker *);

// These functions are used to get and free worker session
extern bool valid_worker_session(worker *);
extern void worker_session_free(worker *);
extern bool set_worker_session_user(worker *, user *);
extern user * get_worker_session_user(worker *);

// The callback function is called when the HTTP transaction has completed
// successfully.
typedef void (*worker_http_cb)(worker *, void *, size_t);

// worker_http performs an HTTP transaction.  When the transaction is
// completed, the supplied callback will be called, with the supplied argument.
// Note that the transaction is performed using the req and res associated with
// the worker.
extern void worker_http(worker *, worker_http_cb);

struct worker_ops {
	int         version;
	const char *type;
	bool (*setup)(worker_config *, controller *, char **);
	void (*teardown)(controller *);
	void (*exec_jsonrpc)(controller *, worker *, const char *, object *);
	void (*get_status)(controller *, worker *);
	void (*create_network)(controller *, worker *, object *);
	void (*get_networks)(controller *, worker *);
	void (*get_network)(controller *, worker *, uint64_t);
	void (*get_members)(controller *, worker *, uint64_t);
	void (*get_member)(controller *, worker *, uint64_t, uint64_t);
	void (*delete_member)(controller *, worker *, uint64_t, uint64_t);
	void (*authorize_member)(controller *, worker *, uint64_t, uint64_t);
	void (*deauthorize_member)(controller *, worker *, uint64_t, uint64_t);
	// Device owners
	void (*get_own_members)(controller *, worker *, uint64_t);
	void (*get_own_member)(controller *, worker *, uint64_t);
};

#define WORKER_OPS_VERSION 1

extern bool worker_register_ops(worker_ops *);

extern worker_ops controller_zt1_ops;
extern worker_ops controller_ztcentral_ops;

typedef struct moon_config       moon_config;
typedef struct proxy_config      proxy_config;
typedef struct controller_config controller_config;
typedef struct tls_config        tls_config;
typedef struct net_config        net_config;
typedef struct api_config        api_config;
typedef struct role_config       role_config;
typedef struct rolegrp_config    rolegrp_config;

struct moon_config {
	uint64_t ids[2];
};

struct tls_config {
	char *keypass;
	char *keyfile;
	char *cacert;
	bool  insecure;
};

struct role_config {
	char *   name;
	uint64_t mask;
};

struct rolegrp_config {
	char *   name;
	uint64_t mask;
};

struct proxy_config {
	char *   survurl;
	char *   rpcurl;
	int      nworkers;
	uint64_t role_add;
	uint64_t role_del;
};

struct controller_config {
	object  *json;
	char *   name;
	char *   url;
	char *   secret;
	char *   type;
	uint64_t nodeid;
	uint64_t allow; // mask of allowed roles
	uint64_t deny;  // mask of denied roles
};

struct api_config {
	char *   method;
	uint64_t allow; // mask of allowed roles
	uint64_t deny;  // mask of denied roles
};

struct net_config {
	uint64_t nwid;
	uint64_t allow; // mask of allowed roles
	uint64_t deny;  // mask of denied roles
};

// A worker_config has the JSON tree associated with it and references
// that.  The configuration is destroyed at the same time the tree is.
struct worker_config {
	object *           json;         // JSON for the entire tree
	tls_config         tls;          // TLS settings
	int                nproxies;     // Number of proxies
	proxy_config *     proxies;      // Proxy structures
	int                ncontrollers; // Number of controllers
	controller_config *controllers;  // Controller structures
	int                nroles;       // Number of roles (permissions)
	role_config *      roles;        // Role (name & bit)
	int                nrolegrps;    // Number of role groups
	rolegrp_config *   rolegrps;     // Role group (name & mask)
	int                napis;
	api_config *       apis;
	int                nnets;
	net_config *       nets;
	char *             zthome;
	char *             userdir;
	char *             tokendir;
	int                nmoons; // Number of moons
	moon_config *      moons;  // ZeroTier moon structure
	int                debug;
};

struct worker {
	proxy *          proxy;
	nng_ctx          ctx; // REP context
	nng_http_req *   req;
	nng_http_res *   res;
	nng_aio *        aio;
	worker_state     state;
	nng_http_client *client;
	uint64_t         id; // request ID of pending request
	response *       resp;
	worker_http_cb   http_cb;
	const char *     method; // RPC method called
	uint64_t         user_roles;
	uint64_t         eff_roles; // roles as modified by proxy changes
	object          *session; // session object store
	result_callback   on_result;
	error_callback    on_error;
};

extern bool get_controller_param(worker *w, object *params, controller **cpp);

extern bool get_auth_param(worker *w, object *params, user **userp);


// Worker methods
extern void create_auth_token(worker *, object *);
extern void delete_auth_token(worker *, object *);
extern void get_auth_token(worker *, object *);
extern void get_auth_tokens(worker *, object *);
extern void set_own_password(worker *, object *);
extern void create_own_totp(worker *, object *);
extern void delete_own_totp(worker *, object *);
extern void validate_config(worker *, object *);
extern void restart_server(worker *, object *);
extern void rpc_create_user(worker *, object *);
extern void rpc_delete_user(worker *, object *);
extern void rpc_get_user(worker *, object *);
extern void rpc_get_user_names(worker *, object *);
extern void rpc_get_own_user(worker *, object *);
extern void add_own_device(worker *, object *);
extern void delete_own_device(worker *, object *);


#endif // WORKER_H
