#!/usr/bin/env bash

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

  options=''
  CPPFLAGS=''

  if [[ "${_CONFIG}" != *'debug'* ]]; then
    CPPFLAGS+=' -DNDEBUG'
  fi

  # Avoid finding unnecessary system (Homebrew, or system for libxml2) packages and the log noise with it.
  options+=' -DOPENSSL_INCLUDE_DIR= -DLIBXML2_INCLUDE_DIR='

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    -DENABLE_LIB_ONLY=ON \
    -DBUILD_STATIC_LIBS=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF \
    -DENABLE_DOC=OFF \
    -DCMAKE_C_FLAGS="${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL}"

  cmake --build "${_BLDDIR}"
  cmake --install "${_BLDDIR}" --prefix "${_PP}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/nghttp2/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}"/include/nghttp2
  mkdir -p "${_DST}"/lib

  cp -f -p "${_PP}"/include/nghttp2/*.h "${_DST}"/include/nghttp2/
  cp -f -p "${_PP}"/lib/*.a             "${_DST}"/lib/
  cp -f -p ChangeLog                    "${_DST}"/ChangeLog.txt
  cp -f -p AUTHORS                      "${_DST}"/AUTHORS.txt
  cp -f -p COPYING                      "${_DST}"/COPYING.txt
  cp -f -p README.rst                   "${_DST}"/

  ../_pkg.sh "$(pwd)/${_ref}"
)
