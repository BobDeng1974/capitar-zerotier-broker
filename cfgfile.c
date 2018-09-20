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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfgfile.h"
#include "object.h"

enum { STATE_BEGIN, STATE_NORMAL, STATE_COMMENT };

object *
cfgfile_load(const char *path)
{
	FILE *      f;
	object *    tree;
	char *      buf;
	size_t      len;
	size_t      i;
	int         c;
	const char *ep;
	int         state;

	if ((f = fopen(path, "rb")) == NULL) {
		fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
		return (NULL);
	}

	// Find the file size.
	if (fseek(f, 0, SEEK_END) < 0) {
		fprintf(stderr, "fseek: %s\n", strerror(errno));
		fclose(f);
		return (NULL);
	}
	len = (size_t) ftell(f);
	if (fseek(f, 0, SEEK_SET) < 0) {
		fprintf(stderr, "fseek: %s\n", strerror(errno));
		fclose(f);
		return (NULL);
	}
	if (len == 0) {
		fprintf(stderr, "%s: empty file\n", path);
		fclose(f);
		return (NULL);
	}
	if ((buf = malloc(len)) == NULL) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		fclose(f);
		return (NULL);
	}

	// Read, but strip out comments while doing it.  This can lead to
	// a smaller length overall.
	i     = 0;
	state = STATE_BEGIN;
	while (len-- > 0) {
		if ((c = fgetc(f)) == EOF) {
			break;
		}

		switch (state) {
		case STATE_BEGIN:
			switch (c) {
			case ' ':
			case '\t':
				buf[i++] = c;
				break;
			case '#':
				state = STATE_COMMENT;
				break;
			default:
				state    = STATE_NORMAL;
				buf[i++] = c;
				break;
			}
			break;
		case STATE_COMMENT:
			if (c == '\n') {
				buf[i++] = c;
				state    = STATE_BEGIN;
			}
			break;
		case STATE_NORMAL:
			buf[i++] = c;
			if (c == '\n') {
				state = STATE_BEGIN;
			}
			break;
		}
	}

	fclose(f);

	tree = parse_obj(buf, i);
	free(buf);
	if (tree == NULL) {
		fprintf(stderr, "%s: Parse error\n", path);
		return (NULL);
	}
	return (tree);
}
