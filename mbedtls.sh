#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} \
    '-DMBEDTLS_FATAL_WARNINGS=OFF' \
    '-DENABLE_PROGRAMS=OFF' \
    '-DENABLE_TESTING=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Make steps for determinism

  readonly _ref='ChangeLog'

  # shellcheck disable=SC2086
  "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/mbedtls/*.h
  touch -c -r "${_ref}" "${_PP}"/include/psa/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/mbedtls"
  mkdir -p "${_DST}/include/psa"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/mbedtls/*.h "${_DST}/include/mbedtls/"
  cp -f -p "${_PP}"/include/psa/*.h     "${_DST}/include/psa/"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib/"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p README.md                    "${_DST}/"
  cp -f -p LICENSE                      "${_DST}/LICENSE.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
