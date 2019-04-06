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

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <nng/supplemental/http/http.h>

#include "object.h"
#include "worker.h"

// This macro makes us do asprintf conditionally.
#define ERRF(strp, fmt, ...) \
        if (strp != NULL)    \
        asprintf(strp, fmt, ##__VA_ARGS__)

struct controller {
        char *             addr;
        char *             name;
        char *             secret;
        char *             host; // for HTTP
        nng_http_client *  client;
        worker_ops *       ops;
        controller_config *config;
	int                debug;
};


#endif // CONTROLLER_H
