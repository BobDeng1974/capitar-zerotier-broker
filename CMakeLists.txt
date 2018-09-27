#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 3.1)

project(ztc C)
cmake_policy(SET CMP0028 NEW)
set(CMAKE_C_STANDARD 99)

include (CheckSymbolExists)

find_package(Threads)
find_package(zerotiercore REQUIRED)
find_package(nng CONFIG REQUIRED)

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
        set(PATH_SEP "\\")
else()
        set(PATH_SEP "/")
endif()


check_symbol_exists(asprintf stdio.h HAVE_ASPRINTF)
check_symbol_exists(unlink unistd.h HAVE_UNLINK)
check_symbol_exists(access, unistd.h, HAVE_ACCESS)
check_symbol_exists(opendir dirent.h HAVE_OPENDIR)

configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(${PROJECT_NAME}-worker worker.c cJSON.c auth.c central.c controller.c cfgfile.c object.c util.c)
target_link_libraries(${PROJECT_NAME}-worker nng::nng)

add_executable(${PROJECT_NAME}-proxy proxy.c cJSON.c cfgfile.c object.c util.c)
target_link_libraries(${PROJECT_NAME}-proxy nng::nng)
