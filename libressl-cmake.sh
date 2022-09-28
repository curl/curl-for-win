#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  CFLAGS="-ffile-prefix-map=$(pwd)="

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} \
    '-DLIBRESSL_APPS=OFF' \
    '-DLIBRESSL_TESTS=OFF' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Build fixups for CMake

  # CMake creates static libs with version numbers in them,
  # e.g. libcrypto-49.a. Strangely the .pc files do not have
  # them.
  # Strip those to make them findable by other projects.
  for l in libcrypto libssl libtls; do
    mv "${_PP}/lib/${l}"*.a "${_PP}/lib/${l}.a"
  done

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # List files created
  find "${_PP}" | grep -a -v -F '/share/' | sort

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_PP}"/include/*.h         "${_DST}/include/"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README.md                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
