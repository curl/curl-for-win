#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} \
    '-DMBEDTLS_FATAL_WARNINGS=OFF' \
    '-DENABLE_PROGRAMS=OFF' \
    '-DENABLE_TESTING=OFF' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/mbedtls/*.h
  touch -c -r "${_ref}" "${_pkg}"/include/psa/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/mbedtls"
  mkdir -p "${_DST}/include/psa"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/mbedtls/*.h "${_DST}/include/mbedtls/"
  cp -f -p "${_pkg}"/include/psa/*.h     "${_DST}/include/psa/"
  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib/"
  cp -f -p ChangeLog                     "${_DST}/ChangeLog.txt"
  cp -f -p README.md                     "${_DST}/"
  cp -f -p LICENSE                       "${_DST}/LICENSE.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
