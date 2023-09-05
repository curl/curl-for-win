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

  CPPFLAGS='-DNDEBUG'

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} \
    '-DENABLE_LIB_ONLY=ON' \
    '-DENABLE_STATIC_LIB=ON' \
    '-DENABLE_SHARED_LIB=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}" \
    "-DCMAKE_CXX_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  # shellcheck disable=SC2086
  "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/nghttp3/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/nghttp3"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/nghttp3/*.h "${_DST}/include/nghttp3/"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib/"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                      "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README.rst                   "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
