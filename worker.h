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

// RPC VERSION number.  Remember to bump according to SemVer.
#ifndef RPC_VERSION
#define RPC_VERSION "1.0"
#endif

enum worker_errors {
	E_BADREQUEST = -32600, // Invalid Request
	E_BADMETHOD  = -32601, // Method not found
	E_BADPARAMS  = -32602, // Invalid params
	E_INTERNAL   = -32000, // Internal error (see message)
	E_NOMEM      = -32001, // Out of memory
	E_BADJSON    = -32002, // Bad JSON from backend
	E_NOCTRLR    = -32003, // Specified controller does not exist
	E_AUTHFAIL   = 4010,   // Authentication well-formed, but invalid
	E_AUTHTOKEN  = 4011,   // API token (bearer) needed
	E_AUTHBASIC  = 4012,   // Basic auth (username / password) needed
	E_AUTHOTP    = 4013,   // Basic+OTP auth needed
	E_FORBIDDEN  = 403,    // Forbidden (insufficient permission)
};

typedef struct worker_ops worker_ops;
typedef struct worker     worker;
typedef struct controller controller;

// when authenticating a user using username/password, we return the actual
// user structure.  As we only do this for auth methods, we want the
// user structure.

extern const char *get_controller_host(controller *);
extern const char *get_controller_secret(controller *);

// send_resp sends a response object (on success).
extern void send_result(worker *, object *);

// send_err sends an error with the given status code, and reason.
extern void send_err(worker *, int, const char *);

// nwid_allowed checks if the given the network id is permitted to be
// shown.  It returns false if the nwid is not to be exposed over the
// RPC interface.
extern bool nwid_allowed(uint64_t);

// These functions are intended for the implementation to use when
// communicating with the HTTP backend controller or central.
extern nng_http_req *worker_http_req(worker *);
extern nng_http_res *worker_http_res(worker *);

// The callback function is called when the HTTP transaction has completed
// successfully.
typedef void (*worker_http_cb)(worker *, void *, size_t);

// worker_http performs an HTTP transaction.  When the transaction is
// completed, the supplied callback will be called, with the supplied argument.
// Note that the transaction is performed using the req and res associated with
// the worker.
extern void worker_http(worker *, worker_http_cb);

struct worker_ops {
	int version;
	void (*get_status)(controller *, worker *);
	void (*get_networks)(controller *, worker *);
	void (*get_network)(controller *, worker *, uint64_t);
	void (*get_members)(controller *, worker *, uint64_t);
	void (*get_member)(controller *, worker *, uint64_t, uint64_t);
	void (*delete_member)(controller *, worker *, uint64_t, uint64_t);
	void (*authorize_member)(controller *, worker *, uint64_t, uint64_t);
	void (*deauthorize_member)(controller *, worker *, uint64_t, uint64_t);
};

#define WORKER_OPS_VERSION 0

extern bool worker_register_ops(const char *, worker_ops *);

extern worker_ops controller_ops;
extern worker_ops central_ops;

typedef struct proxy_config      proxy_config;
typedef struct controller_config controller_config;
typedef struct worker_config     worker_config;
typedef struct tls_config        tls_config;
typedef struct net_config        net_config;
typedef struct api_config        api_config;
typedef struct role_config       role_config;

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

struct proxy_config {
	char *   survurl;
	char *   rpcurl;
	int      nworkers;
	uint64_t roles;
};

struct controller_config {
	char *name;
	char *url;
	char *secret;
	char *type;
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
	                // alternatively:
	                // int nperms;
	                // struct { bool allow; uint64_t role };
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
	int                nroles;
	role_config *      roles;
	int                napis;
	api_config *       apis;
	int                nnets;
	net_config *       nets;
	char *             zthome;
	char *             userdir;
	char *             tokendir;
};

#endif // WORKER_H
