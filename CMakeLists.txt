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

find_package(nng CONFIG REQUIRED)

add_executable(${PROJECT_NAME}-worker worker.c cJSON.c central.c controller.c cfgfile.c object.c)
target_link_libraries(${PROJECT_NAME}-worker nng::nng)

add_executable(${PROJECT_NAME}-proxy proxy.c cJSON.c cfgfile.c object.c)
target_link_libraries(${PROJECT_NAME}-proxy nng::nng)
