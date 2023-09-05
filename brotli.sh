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
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DBROTLI_DISABLE_TESTS=ON' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # libcurl does not need the encoding functionality
  rm -f "${_PP}"/include/encode.h
  rm -f "${_PP}"/lib/libbrotlienc.a
  rm -f "${_PP}"/lib/pkgconfig/libbrotlienc.pc

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='docs/brotli.1'

  # shellcheck disable=SC2086
  "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/brotli/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/brotli"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/brotli/*.h "${_DST}/include/brotli/"
  cp -f -p "${_PP}"/lib/*.a            "${_DST}/lib/"
  cp -f -p README.md                   "${_DST}/"
  cp -f -p LICENSE                     "${_DST}/LICENSE.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
