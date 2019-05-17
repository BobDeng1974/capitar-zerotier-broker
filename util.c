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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <nng/nng.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>
#include <nng/transport/zerotier/zerotier.h>

#include "object.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

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

bool
empty(const char *s1)
{
	if ((s1 == NULL) || (strcmp(s1, "") == 0)) {
		return (true);
	}
	return (false);
}

// better than strcmp because it is NULL safe, and uses more natural booleans.
// (returns false if either is NULL, or strcmp != 0).
bool
samestr(const char *s1, const char *s2)
{
	if ((s1 == NULL) || (s2 == NULL) || (strcmp(s1, s2) != 0)) {
		return (false);
	}
	return (true);
}

void
to_lower(char *str) {
	for(int i = 0; str[i]; i++){
		str[i] = tolower(str[i]);
	}
}

object *
get_ifaddrs()
{

	struct ifaddrs *ifa, *ifa_tmp;
	char addr[50];
	char ztif[] = "zt";

	object * ifaddrs = alloc_obj();
	object * ip4 = alloc_arr();
	add_obj_obj(ifaddrs, "ip4", ip4);
	object * ip6 = alloc_arr();
	add_obj_obj(ifaddrs, "ip6", ip6);

	if (getifaddrs(&ifa) == -1) {
		perror("getifaddrs failed");
		return (ifaddrs);
	}

	ifa_tmp = ifa;
	while (ifa_tmp) {
		if ((samestr(ifa_tmp->ifa_name, "lo")) ||
		    (!strncmp(ifa_tmp->ifa_name, ztif, 2))) {
		} else if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                              (ifa_tmp->ifa_addr->sa_family == AF_INET6))) {
			if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
				// create IPv4 string
				struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
				inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
				add_arr_string(ip4, addr);
			} else { // AF_INET6
				// create IPv6 string
				struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
				inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
				add_arr_string(ip6, addr);
			}
			//printf("%s: %s\n", ifa_tmp->ifa_name, addr);
		}
		ifa_tmp = ifa_tmp->ifa_next;
	}
	return (ifaddrs);
}

void
set_local_addr(nng_listener l)
{

	struct ifaddrs *ifa, *ifa_tmp;
	int rv;

	// We do not want to use ZeroTier twice
	char ztif[] = "zt"; // ZeroTier tap interfaces start with zt

	nng_sockaddr locaddr;
	nng_sockaddr udp4_addr;
	nng_sockaddr udp6_addr;

	rv = nng_listener_setopt(
	   l, NNG_OPT_ZT_CLEAR_LOCAL_ADDRS, 0, 0);
	if (rv != 0) {
		printf("Error clearing local addresses: %d\n", rv);
	}

	rv = nng_listener_getopt_sockaddr(
		l, NNG_OPT_ZT_UDP4_ADDR, &udp4_addr);
	if (rv != 0) {
		printf("Error geting zt udp4 adress: %d\n", rv);
	}

	//printf("udp4 port: %d\n", ntohs(udp4_addr.s_in.sa_port));

	rv = nng_listener_getopt_sockaddr(
		l, NNG_OPT_ZT_UDP6_ADDR, &udp6_addr);
	if (rv != 0) {
		printf("Error geting zt udp6 adress: %d\n", rv);
	}

	//printf("udp6 port: %d\n", ntohs(udp6_addr.s_in6.sa_port));

	if (getifaddrs(&ifa) == -1) {
		perror("getifaddrs failed");
		return;
	}

	ifa_tmp = ifa;
	while (ifa_tmp) {
		if ((samestr(ifa_tmp->ifa_name, "lo")) ||
		    (!strncmp(ifa_tmp->ifa_name, ztif, 2))) {
		} else if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                              (ifa_tmp->ifa_addr->sa_family == AF_INET6))) {
			if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
				locaddr.s_family = AF_INET;
				locaddr.s_in.sa_family = NNG_AF_INET;
				struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
				locaddr.s_in.sa_addr = in->sin_addr.s_addr;
				locaddr.s_in.sa_port = udp4_addr.s_in.sa_port;
				rv = nng_listener_setopt(
				    l, NNG_OPT_ZT_ADD_LOCAL_ADDR, &locaddr, sizeof(locaddr));
				if (rv != 0) {
					printf("Error adding local ipv4 address: %d\n", rv);
				}
			} else { // AF_INET6
				locaddr.s_family = AF_INET6;
				locaddr.s_in.sa_family = NNG_AF_INET6;
				struct sockaddr_in6 *in = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
				memcpy(&locaddr.s_in6.sa_addr, in->sin6_addr.s6_addr, 16);
				locaddr.s_in6.sa_port = udp4_addr.s_in6.sa_port;
				rv = nng_listener_setopt(
				    l, NNG_OPT_ZT_ADD_LOCAL_ADDR, &locaddr, sizeof(locaddr));
				if (rv != 0) {
					printf("Error adding local ipv6 address: %d\n", rv);
				}
			}
		}
		ifa_tmp = ifa_tmp->ifa_next;
	}
}
