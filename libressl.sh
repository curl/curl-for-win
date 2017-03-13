#!/bin/sh -ex

# Copyright 2014-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_cpu="$2"

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
  [ "${_cpu}" = '32' ] && OPTIONS=--host=i686-w64-mingw32
  [ "${_cpu}" = '64' ] && OPTIONS=--host=x86_64-w64-mingw32

  export LDFLAGS="-m${_cpu}"
  export CFLAGS="${LDFLAGS} -fno-ident"
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"

  # FIXME: Burnt-in prefix is not fully deterministic. It has 'C:/msys64' prepended.

  # shellcheck disable=SC2086
  ./configure ${OPTIONS} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    '--prefix=/usr/local' \
    --silent
# make clean > /dev/null
  make install "DESTDIR=$(pwd)/pkg" > /dev/null

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" -p -s ${_pkg}/bin/*.exe
  "${_CCPREFIX}strip" -p -s ${_pkg}/bin/*.dll

  ../_peclean.py "${_ref}" "${_pkg}/bin/*.exe"
  ../_peclean.py "${_ref}" "${_pkg}/bin/*.dll"

  ../_sign.sh "${_pkg}/bin/*.exe"
  ../_sign.sh "${_pkg}/bin/*.dll"

  touch -c -r "${_ref}" ${_pkg}/etc/ssl/cert.pem
  touch -c -r "${_ref}" ${_pkg}/etc/ssl/*.cnf
  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/bin/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ./*.pc
  touch -c -r "${_ref}" ${_pkg}/include/openssl/*.h
  touch -c -r "${_ref}" ${_pkg}/include/*.h

  # Tests

  ${_WINE} ${_pkg}/bin/openssl.exe version
  ${_WINE} ${_pkg}/bin/openssl.exe ciphers

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/etc/ssl/cert.pem    "${_DST}/cert.pem"
  cp -f -p ${_pkg}/etc/ssl/*.cnf       "${_DST}/"
  cp -f -p ${_pkg}/bin/*.exe           "${_DST}/"
  cp -f -p ${_pkg}/bin/*.dll           "${_DST}/"
  cp -f -p ${_pkg}/lib/*.a             "${_DST}/lib"
  cp -f -p ./*.pc                      "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p ${_pkg}/include/*.h         "${_DST}/include/"
  cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                     "${_DST}/COPYING.txt"
  cp -f -p README.md                   "${_DST}/"

  unix2dos -k "${_DST}"/*.md
  unix2dos -k "${_DST}"/*.txt

  # Copy libs to an OpenSSL-compatible location so that libssh2 and curl find them.
  cp -f -p ${_pkg}/lib/* ./

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
