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

#ifndef OBJECT_H
#define OBJECT_H

// This API wraps some other underlying JSON API.  This gives us a chance
// to provide both more convenient functions, and also to isolate the JSON
// layer -- there are numerous JSON C libraries, and it would be nice to
// be able to change them without having to touch everything.

#include <stdbool.h>
#include <stdint.h>

typedef struct object object;
typedef struct array  array;

// load and save JSON to external files
extern object *obj_load(const char *, char **);
extern bool    obj_save(const char *, object *, char **);

extern object *alloc_arr(void);
extern object *alloc_obj(void);
extern void    free_obj(object *);
extern object *parse_obj(const void *, size_t);
extern char *  print_obj(const object *);
extern object *clone_obj(const object *);
extern bool    get_obj_string(object *, const char *, char **);
extern bool    get_obj_uint64(object *, const char *, uint64_t *);
extern bool    get_obj_number(object *, const char *, double *);
extern bool    get_obj_int(object *, const char *, int *);
extern bool    get_obj_bool(object *, const char *, bool *);
extern bool    get_obj_obj(object *, const char *, object **);
extern bool    add_obj_int(object *, const char *, int);
extern bool    add_obj_string(object *, const char *, const char *);
extern bool    add_obj_bool(object *, const char *, bool);
extern bool    add_obj_uint64(object *, const char *, uint64_t);
extern bool    add_obj_number(object *, const char *, double);
extern bool    add_obj_obj(object *, const char *, object *);
extern int     get_arr_len(object *);
extern bool    get_arr_obj(object *, int, object **);
extern bool    get_arr_string(object *, int, char **);
extern bool    add_arr_string(object *, const char *);
extern bool    add_arr_obj(object *, object *);
extern bool    is_obj_array(object *);
extern bool    is_obj_object(object *);
extern char *  next_obj_key(object *, const char *);
extern bool    del_arr_item(object *, int);
extern bool    del_obj_item(object *, const char *);


#endif // OBJECT_H
