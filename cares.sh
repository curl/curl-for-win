#!/bin/sh -ex

# Copyright 2014-present Viktor Szakats. See LICENSE.md

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
    '-DCARES_STATIC=ON' \
    '-DCARES_STATIC_PIC=ON' \
    '-DCARES_SHARED=OFF' \
    '-DCARES_BUILD_TESTS=OFF' \
    '-DCARES_BUILD_CONTAINER_TESTS=OFF' \
    '-DCARES_BUILD_TOOLS=OFF' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete the implib (when CARES_SHARED=ON)
  rm -f "${_pkg}"/lib/*.dll.a
  # Delete '-static' suffix (when CARES_SHARED=ON)
  [ -f "${_pkg}"/lib/libcares_static.a ] && mv -f "${_pkg}"/lib/libcares_static.a "${_pkg}"/lib/libcares.a

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='RELEASE-NOTES'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/*.h  "${_DST}/include/"
  cp -f -p "${_pkg}"/lib/*.a      "${_DST}/lib/"
  cp -f -p README.md              "${_DST}/"
  cp -f -p CHANGES                "${_DST}/CHANGES.txt"
  cp -f -p RELEASE-NOTES          "${_DST}/RELEASE-NOTES.txt"
  cp -f -p LICENSE.md             "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
