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

// Implement our "object" interface in terms of cJSON.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "object.h"

// An object is a cJSON item.  (Identity for now.)
struct object {
	cJSON json;
};

object *
alloc_obj(void)
{
	return ((object *) cJSON_CreateObject());
}

void
free_obj(object *o)
{
	cJSON_Delete(&o->json);
}

object *
parse_obj(const void *str, size_t len)
{
	return ((object *) cJSON_ParseWithLen(str, NULL, 0, len));
}

char *
print_obj(const object *o)
{
	return (cJSON_Print(&o->json));
}

object *
clone_obj(const object *o)
{
	return ((object *) cJSON_Duplicate(&o->json, 1));
}

bool
get_obj_string(object *o, const char *name, char **strp)
{
	cJSON *t;
	char * s;
	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	if (((t = cJSON_GetObjectItemCaseSensitive(&o->json, name)) == NULL) ||
	    ((s = cJSON_GetStringValue(t)) == NULL)) {
		return (false);
	}
	*strp = s;
	return (true);
}

bool
get_obj_uint64(object *o, const char *name, uint64_t *valp)
{

	cJSON *            t;
	char *             s;
	char *             ep;
	unsigned long long val;

	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	if ((t = cJSON_GetObjectItemCaseSensitive(&o->json, name)) == NULL) {
		return (false);
	}
	if (cJSON_IsNumber(t)) {
		*valp = (uint64_t) t->valuedouble;
		return (true);
	}
	if ((s = cJSON_GetStringValue(t)) == NULL) {
		return (false);
	}
	val = strtoull(s, &ep, 16);
	if ((ep == s) || (*ep != '\0')) {
		return (false);
	}
	*valp = val;
	return (true);
}

bool
get_obj_int(object *o, const char *name, int *valp)
{
	cJSON *t;

	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	if (((t = cJSON_GetObjectItemCaseSensitive(&o->json, name)) == NULL) ||
	    (!cJSON_IsNumber(t))) {
		return (false);
	}
	if (t->valueint != t->valuedouble) {
		return (false); // not representable within an integer
	}
	*valp = t->valueint;
	return (true);
}

bool
get_obj_number(object *o, const char *name, double *valp)
{
	cJSON *t;

	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	if (((t = cJSON_GetObjectItemCaseSensitive(&o->json, name)) == NULL) ||
	    (!cJSON_IsNumber(t))) {
		return (false);
	}
	*valp = t->valuedouble;
	return (true);
}

bool
get_obj_bool(object *o, const char *name, bool *valp)
{
	cJSON *t;

	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	if ((t = cJSON_GetObjectItemCaseSensitive(&o->json, name)) == NULL) {
		return (false);
	}
	if (cJSON_IsTrue(t)) {
		*valp = true;
		return (true);
	}
	if (cJSON_IsFalse(t) || cJSON_IsNull(t)) {
		*valp = false;
		return (true);
	}
	return (false);
}

bool
get_obj_obj(object *o, const char *name, object **valp)
{
	cJSON *t;
	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	if (((t = cJSON_GetObjectItemCaseSensitive(&o->json, name)) == NULL) ||
	    ((!cJSON_IsObject(t)) && (!cJSON_IsArray(t)))) {
		return (false);
	}
	*valp = (object *) t;
	return (true);
}

bool
is_obj_array(object *o)
{
	return (cJSON_IsArray(&o->json) ? true : false);
}

bool
is_obj_object(object *o)
{
	return (cJSON_IsObject(&o->json) ? true : false);
}

bool
add_obj_int(object *o, const char *name, int val)
{
	if ((cJSON_AddNumberToObject(&o->json, name, val)) == NULL) {
		return (false);
	}
	return (true);
}

bool
add_obj_string(object *o, const char *name, const char *s)
{
	if ((cJSON_AddStringToObject(&o->json, name, s)) == NULL) {
		return (false);
	}
	return (true);
}

bool
add_obj_bool(object *o, const char *name, bool b)
{
	if (cJSON_AddBoolToObject(&o->json, name, b) == NULL) {
		return (false);
	}
	return (true);
}

bool
add_obj_uint64(object *o, const char *name, uint64_t val)
{
	char str[32];

	(void) snprintf(str, sizeof(str), "%llx", (unsigned long long) val);
	if ((cJSON_AddStringToObject(&o->json, name, str)) == NULL) {
		return (false);
	}
	return (true);
}

bool
add_obj_number(object *o, const char *name, double val)
{
	if (cJSON_AddNumberToObject(&o->json, name, val) == NULL) {
		return (false);
	}
	return (true);
}

bool
add_obj_obj(object *o, const char *name, object *val)
{
	if (!cJSON_IsObject(&o->json)) {
		return (false);
	}
	cJSON_AddItemToObjectCS(&o->json, name, &val->json);
	return (true);
}

object *
alloc_arr(void)
{
	return ((object *) cJSON_CreateArray());
}

int
get_arr_len(object *arr)
{
	if (!cJSON_IsArray(&arr->json)) {
		return (-1);
	}
	return (cJSON_GetArraySize(&arr->json));
}

bool
get_arr_obj(object *arr, int index, object **objp)
{
	cJSON *t;

	if (((t = cJSON_GetArrayItem(&arr->json, index)) == NULL) ||
	    ((!cJSON_IsObject(t)) && (!cJSON_IsArray(t)))) {
		return (false);
	}
	*objp = (object *) t;
	return (true);
}

bool
get_arr_string(object *arr, int index, char **valp)
{
	cJSON *t;
	char * s;

	if ((!cJSON_IsArray(&arr->json)) ||
	    ((t = cJSON_GetArrayItem(&arr->json, index)) == NULL) ||
	    ((s = cJSON_GetStringValue(t)) == NULL)) {
		return (false);
	}
	*valp = s;
	return (true);
}

bool
add_arr_string(object *obj, const char *s)
{
	cJSON *sobj;

	if ((!cJSON_IsArray(&obj->json)) ||
	    ((sobj = cJSON_CreateString(s)) == NULL)) {
		return (false);
	}
	cJSON_AddItemToArray(&obj->json, sobj);
	return (true);
}

char *
next_obj_key(object *obj, const char *name)
{
	cJSON *child;

	if (!cJSON_IsObject(&obj->json)) {
		return (NULL);
	}

	for (child = obj->json.child; child != NULL; child = child->next) {
		if (name == NULL) {
			return (child->string);
		}
		if (strcmp(name, child->string) == 0) {
			break;
		}
	}
	if ((child == NULL) || (child->next == NULL)) {
		return (NULL);
	}
	return (child->next->string);
}
