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
    '-DCARES_STATIC=ON' \
    '-DCARES_STATIC_PIC=ON' \
    '-DCARES_SHARED=OFF' \
    '-DCARES_BUILD_TESTS=OFF' \
    '-DCARES_BUILD_CONTAINER_TESTS=OFF' \
    '-DCARES_BUILD_TOOLS=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='RELEASE-NOTES'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/*.h "${_DST}/include/"
  cp -f -p "${_PP}"/lib/*.a     "${_DST}/lib/"
  cp -f -p README.md            "${_DST}/"
  cp -f -p CHANGES              "${_DST}/CHANGES.txt"
  cp -f -p RELEASE-NOTES        "${_DST}/RELEASE-NOTES.txt"
  cp -f -p LICENSE.md           "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
