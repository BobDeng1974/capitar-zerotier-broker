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

#include "config.h" // Must be first

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_UNLINK) || defined(HAVE_RENAME) || defined(HAVE_ACCESS)
#include <unistd.h>
#endif

#if defined(HAVE_OPENDIR)
#include <dirent.h>
#endif

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "auth.h"

#ifndef HAVE_ASPRINTF
// This is sort of like asprintf, but asprintf isn't portable, so
// we baked our own.

int
asprintf(char **resp, const char *fmt, ...)
{
	int     len;
	va_list ap;
	char *  s;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (len < 0) {
		*resp = NULL;
		return (-1);
	}
	if ((s = malloc(len + 1)) == NULL) {
		*resp = NULL;
		return (-1);
	}
	va_start(ap, fmt);
	vsnprintf(s, len + 1, fmt, ap);
	va_end(ap);
	*resp = s;
	return (len);
}

#endif

char *
path_join(const char *dir, const char *file, const char *suffix)
{
	char *res;
	if (suffix == NULL) {
		suffix = "";
	}
	if (asprintf(&res, "%s%s%s%s", dir, PATH_SEP, file, suffix) < 0) {
		return (NULL);
	}
	return (res);
}

bool
path_delete(const char *path)
{
#ifdef HAVE_UNLINK
	if (unlink(path) == 0) {
		return (true);
	}
#elif defined(_WIN32)
	if (DeleteFileA(path)) {
		return (true);
	}
#endif
	return (false);
}

bool
path_rename(const char *oldpath, const char *newpath)
{
#ifdef HAVE_RENAME
	if (rename(oldpath, newpath) == 0) {
		return (true);
	}
#elif defined(_WIN32)
	if (MoveFileEx(oldpath, newpath, 1)) {
		return (true);
	}
#endif
	return (false);
}

bool
path_exists(const char *path)
{
#if defined(HAVE_ACCESS)
	if (access(path, F_OK) == 0) {
		return (true);
	}
#elif defined(_WIN32)
	if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
		return (true);
	}
#endif
	return (false);
}

// safe filenames are those that work on Windows, won't be hidden,
// and use printable characters.
bool
safe_filename(const char *name)
{
	int  i;
	char c;
	for (i = 0; (c = name[i]) != '\0'; i++) {
		if (isalnum(c)) {
			continue;
		}
		if (strchr("\\/?:*\"<>|", c) != NULL) {
			return (false);
		}
		if ((i == 0) && (c == '.')) {
			// We are prohibiting names which would be hidden.
			return (false);
		}
		if (!isprint(c)) {
			return (false);
		}
		if (i > 64) {
			return (false);
		}
	}
	if (i == 0) {
		return (false);
	}
	return (true);
}

#ifdef HAVE_OPENDIR
void *
path_opendir(const char *path)
{
	return (opendir(path));
}

void
path_closedir(void *arg)
{
	closedir((DIR *) arg);
}

const char *
path_readdir(void *arg)
{
	DIR *          dirp = arg;
	struct dirent *dent;

	while ((dent = readdir(dirp)) != NULL) {
		// Suppress "hidden" files.
		if (dent->d_name[0] != '.') {
			return (dent->d_name);
		}
	}
	return (NULL);
}
#elif defined(_WIN32)

struct findh {
	HANDLE h;
	WIN32_FIND_DATA ent;
	bool first;
};

void *
path_opendir(char *path)
{
	char name[MAX_PATH + 1];
	struct findh *fh;

	snprintf(name, sizeof(name), "%s\\*", path);

	if (fh = malloc(sizeof(*fh)) == NULL) {
		return (NULL);
	}
	if ((fh->h = FindFirstFileA(name, &fh->ent)) == INVALID_HANDLE_VALUE) {
		free(fh);
		return (NULL);
	}
	fh->first = true;
	return (fh);
}

const char *
path_readdir(void *arg)
{
	struct findh *fh = arg;
	if (fh->first) {
		fh->first = false;
		return (fh->ent.cFileName);
	}
	if (FindNextFileA(fh->h, &fh->ent)) {
		return (fh->ent.cFileName);
	}
	return (NULL);
}

void
path_closedir(void *arg)
{
	struct findh *fh = arg;
	FindClose(fh->h);
	free(fh);
}
#endif // HAVE_OPENDIR
