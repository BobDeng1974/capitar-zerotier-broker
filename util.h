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

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"

#ifndef HAVE_ASPRINTF
extern int asprintf(char **, const char *, ...);
#endif

extern char *      path_join(const char *, const char *, const char *);
extern bool        path_delete(const char *);
extern bool        path_rename(const char *, const char *);
extern bool        safe_filename(const char *);
extern bool        path_exists(const char *);
extern void *      path_opendir(const char *);
extern void        path_closedir(void *);
extern const char *path_readdir(void *);
#endif // UTIL_H
