#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# EXPERIMENTAL.

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DBUILD_SELFTEST=OFF' \
    '-DWOLFSSL_REPRODUCIBLE_BUILD=ON' \
    '-DWOLFSSL_OPENSSLEXTRA=ON' \
    '-DWOLFSSL_AESCTR=ON' \
    '-DWOLFSSL_EXAMPLES=OFF' \
    '-DWOLFSSL_CRYPT_TESTS=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  . ../wolfssl-pkg.sh
)
