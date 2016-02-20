#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_CPU="$2"

(
   cd "${_NAM}" || exit 0

   # Build

   find . -name '*.o'   -type f -delete
   find . -name '*.a'   -type f -delete
   find . -name '*.lo'  -type f -delete
   find . -name '*.la'  -type f -delete
   find . -name '*.lai' -type f -delete
   find . -name '*.Plo' -type f -delete
   find . -name '*.pc'  -type f -delete
   find . -name '*.dll' -type f -delete
   find . -name '*.exe' -type f -delete

   export CC="${_CCPREFIX}gcc -static-libgcc"
   [ "${_CPU}" = '32' ] && OPTIONS=--host=i686-w64-mingw32
   [ "${_CPU}" = '64' ] && OPTIONS=--host=x86_64-w64-mingw32

   export LDFLAGS="-m${_CPU}"
   export CFLAGS="${LDFLAGS} -fno-ident"

   # TOFIX: Burnt-in prefix is not fully deterministic. It has 'C:/msys64' prepended.

   # shellcheck disable=SC2086
   exec 0</dev/null && ./configure ${OPTIONS} --disable-silent-rules '--prefix=/usr/local' --silent
#  exec 0</dev/null && make clean > /dev/null
   exec 0</dev/null && make install "DESTDIR=$(pwd)/pkg" > /dev/null

   # DESTDIR= + --prefix=
   _PKG='pkg/usr/local'

   # Make steps for determinism

   readonly _REF='ChangeLog'

   strip -p --enable-deterministic-archives -g ${_PKG}/lib/*.a
   strip -p -s ${_PKG}/bin/*.exe
   strip -p -s ${_PKG}/bin/*.dll

   ../_peclean.py "${_REF}" "${_PKG}/bin/*.exe"
   ../_peclean.py "${_REF}" "${_PKG}/bin/*.dll"

   touch -c -r "${_REF}" ${_PKG}/etc/ssl/cert.pem
   touch -c -r "${_REF}" ${_PKG}/etc/ssl/*.cnf
   touch -c -r "${_REF}" ${_PKG}/bin/*.exe
   touch -c -r "${_REF}" ${_PKG}/bin/*.dll
   touch -c -r "${_REF}" ${_PKG}/lib/*.a
   touch -c -r "${_REF}" ${_PKG}/include/openssl/*.h
   touch -c -r "${_REF}" ${_PKG}/include/*.h

   # Tests

   ${_PKG}/bin/openssl.exe version
   ${_PKG}/bin/openssl.exe ciphers

   # Create package

   _BAS="${_NAM}-${_VER}-win${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/include/openssl"
   mkdir -p "${_DST}/lib"

   cp -f -p ${_PKG}/etc/ssl/cert.pem    "${_DST}/cert.pem"
   cp -f -p ${_PKG}/etc/ssl/*.cnf       "${_DST}/"
   cp -f -p ${_PKG}/bin/*.exe           "${_DST}/"
   cp -f -p ${_PKG}/bin/*.dll           "${_DST}/"
   cp -f -p ${_PKG}/lib/*.a             "${_DST}/lib"
   cp -f -p ${_PKG}/include/openssl/*.h "${_DST}/include/openssl/"
   cp -f -p ${_PKG}/include/*.h         "${_DST}/include/"
   cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
   cp -f -p COPYING                     "${_DST}/COPYING.txt"
   cp -f -p README.md                   "${_DST}/"

   unix2dos -k "${_DST}"/*.md
   unix2dos -k "${_DST}"/*.txt

   # Copy them to an OpenSSL-compatible location so that libssh2 and curl find them.
   cp -f -p ${_PKG}/lib/* ./

   ../_pack.sh "$(pwd)/${_REF}"
   ../_ul.sh
)
