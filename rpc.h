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

#ifndef RPC_H
#define RPC_H

// RPC VERSION number.  Remember to bump according to SemVer.
#ifndef RPC_VERSION
#define RPC_VERSION "1.0"
#endif

enum rpc_errors {
	E_BADREQUEST = -32600, // Invalid Request
	E_BADMETHOD  = -32601, // Method not found
	E_BADPARAMS  = -32602, // Invalid params
	E_INTERNAL   = -32000, // Internal error (see message)
	E_NOMEM      = -32001, // Out of memory
	E_BADJSON    = -32002, // Bad JSON from backend
	E_NOCTRLR    = -32003, // Specified controller does not exist
	E_AUTHREQD   = 4010,   // Authentication required
	E_AUTHFAIL   = 4011,   // Authentication well-formed, but invalid
	E_AUTHOTP    = 4012,   // Basic+OTP auth needed
	E_AUTHTOKEN  = 4013,   // Invalid token presented
	E_AUTHEXPIRE = 4014,   // Bearer token expired
	E_FORBIDDEN  = 403,    // Forbidden (insufficient permission)
};

// clang-format off
#define METHOD_GET_STATUS	"get-status"
#define	METHOD_LIST_NETWORKS	"get-networks"
#define	METHOD_GET_NETWORK	"get-network"
#define	METHOD_LIST_MEMBERS	"get-network-members"
#define	METHOD_GET_MEMBER	"get-network-member"
#define	METHOD_DELETE_MEMBER	"delete-network-member"
#define	METHOD_AUTH_MEMBER	"authorize-network-member"
#define METHOD_DEAUTH_MEMBER	"deauthorize-network-member"
#define	METHOD_CREATE_TOKEN	"create-auth-token"
#define	METHOD_DELETE_TOKEN	"delete-auth-token"
#define METHOD_GET_TOKEN	"get-token"
#define METHOD_GET_TOKENS	"get-tokens"
#define METHOD_SET_PASSWD	"set-password"
#define METHOD_CREATE_TOTP	"create-totp"
//clang-format on

#endif // RPC_H
