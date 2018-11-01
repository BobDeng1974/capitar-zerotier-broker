#!/usr/bin/env bash
#
# This script exists mostly because figuring out how to make
# CMake deal with multiple dependencies and NNG is simply *too hard*.
# Probably we need to come up with a better solution for NNG and its
# dependencies on ZeroTierOne and mbedTLS.
#

cmake="cmake -GNinja -DBUILD_SHARED_LIBS=OFF"

if [ -z "$1" ]
then
	echo "Usage: $0 <build-dir>"
	exit 1
fi

mkdir -p $1 || exit
bindir="$(cd $1; pwd)"
srcdir="$(cd $(dirname $0); pwd)"
blddir="${bindir}/build"
insdir="${bindir}/install"

git submodule update --init --recursive

repos="mbedtls libzerotiercore nng"

# We build all components in an "install" subdirectory of the build directory
# We also search for local dependencies there.
cf="-DCMAKE_INSTALL_PREFIX=${insdir} -DCMAKE_PREFIX_PATH=${insdir}"
mbedtls_cf="${cf}"
libzerotiercore_cf="${cf}"
nng_cf="${cf} -DNNG_ENABLE_TLS=ON -DNNG_TRANSPORT_ZEROTIER=ON -DNNG_SETSTACKSIZE=ON"

for repo in $repos
do
	echo "###"
	echo "### Building ${repo}"
	echo "###"

	mkdir -p ${blddir}/${repo}
	cmflags=$(eval echo '$'${repo}_cf)
	(
		cd ${blddir}/${repo} &&
		${cmake} ${cmflags} ${srcdir}/extern/${repo} &&
		ninja &&
		ninja install
	)
done

cd ${bindir}
${cmake} -DCMAKE_PREFIX_PATH=${insdir} ${srcdir} &&
ninja
