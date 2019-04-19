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
	E_EXISTS     = -32603, // Object already exists
	E_NOTFOUND   = -32603, // Object not found
	E_INTERNAL   = -32000, // Internal error (see message)
	E_NOMEM      = -32001, // Out of memory
	E_BADJSON    = -32002, // Bad JSON from backend
	E_NOCTRLR    = -32003, // Specified controller does not exist
	E_BADCONFIG  = -32004, // Bad configuration file
	E_AUTHREQD   = 4010,   // Authentication required
	E_AUTHFAIL   = 4011,   // Authentication well-formed, but invalid
	E_AUTHOTP    = 4012,   // Basic+OTP auth needed
	E_AUTHTOKEN  = 4013,   // Invalid token presented
	E_AUTHEXPIRE = 4014,   // Bearer token expired
	E_FORBIDDEN  = 403,    // Forbidden (insufficient permission)
};

// clang-format off
#define METHOD_GET_STATUS			"get-status"
#define	METHOD_CREATE_NETWORK			"create-network"
#define	METHOD_LIST_NETWORKS			"get-networks"
#define	METHOD_GET_NETWORK			"get-network"
#define	METHOD_DELETE_NETWORK			"delete-network"
#define	METHOD_LIST_MEMBERS			"get-network-members"
#define	METHOD_GET_MEMBER			"get-network-member"
#define	METHOD_DELETE_MEMBER			"delete-network-member"
#define	METHOD_AUTH_MEMBER			"authorize-network-member"
#define METHOD_DEAUTH_MEMBER			"deauthorize-network-member"

// Network owners
#define	METHOD_DELETE_OWN_NETWORK		"delete-own-network"
#define	METHOD_GET_OWN_NETWORK			"get-own-network"
#define	METHOD_LIST_OWN_NETWORK_MEMBERS		"get-own-network-members"
#define	METHOD_GET_OWN_NETWORK_MEMBER		"get-own-network-member"
#define	METHOD_DELETE_OWN_NETWORK_MEMBER	"delete-own-network-member"
#define	METHOD_AUTH_OWN_NETWORK_MEMBER		"authorize-own-network-member"
#define METHOD_DEAUTH_OWN_NETWORK_MEMBER	"deauthorize-own-network-member"

// Device owners
#define	METHOD_LIST_NETWORK_OWN_MEMBERS		"get-network-own-members"
#define	METHOD_GET_NETWORK_OWN_MEMBER		"get-network-own-member"
#define	METHOD_DELETE_NETWORK_OWN_MEMBER	"delete-network-own-member"
#define	METHOD_AUTH_NETWORK_OWN_MEMBER		"authorize-network-own-member"
#define METHOD_DEAUTH_NETWORK_OWN_MEMBER	"deauthorize-network-own-member"

#define	METHOD_CREATE_TOKEN			"create-auth-token"
#define	METHOD_DELETE_TOKEN			"delete-auth-token"
#define METHOD_GET_TOKEN			"get-token"
#define METHOD_GET_TOKENS			"get-tokens"
#define METHOD_SET_PASSWD			"set-password"
#define METHOD_CREATE_TOTP			"create-totp"
#define METHOD_DELETE_TOTP			"delete-totp"
#define	METHOD_VALIDATE_CONFIG			"validate-config"
#define	METHOD_RESTART_SERVICE			"restart-service"
#define METHOD_ADD_OWN_DEVICE			"add-own-device"
#define METHOD_DELETE_OWN_DEVICE		"delete-own-device"
#define METHOD_ENROLL_OWN_DEVICE		"enroll-own-device"
#define	METHOD_CREATE_USER			"create-user"
#define	METHOD_ASSIGN_USER_ROLE			"assign-user-role"
#define	METHOD_REVOKE_USER_ROLE			"revoke-user-role"
#define	METHOD_DELETE_USER			"delete-user"
#define METHOD_GET_USER				"get-user"
#define METHOD_GET_USERNAMES			"get-usernames"
#define METHOD_GET_OWN_USER			"get-own-user"
//clang-format on

#endif // RPC_H
