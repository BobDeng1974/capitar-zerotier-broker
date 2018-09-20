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
};

typedef struct worker_ops worker_ops;
typedef struct worker     worker;
typedef struct controller controller;

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
	void (*get_status)(controller *, worker *);
	void (*get_networks)(controller *, worker *);
	void (*get_network)(controller *, worker *, uint64_t);
	void (*get_members)(controller *, worker *, uint64_t);
	void (*get_member)(controller *, worker *, uint64_t, uint64_t);
};

extern worker_ops controller_ops;

#endif // WORKER_H
