#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL}"

  # FIXME: As of zlib 1.2.12, its CMakeLists.txt prevents passing custom RCFLAGS
  #        to the RC command. Use our wrapper as a work around.
  #        PR: https://github.com/madler/zlib/pull/677
  [ -n "${_RC_WRAPPER}" ] && RC="${_RC_WRAPPER}"

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  ls -l "${_pkg}"/lib/*.a

  # We need the static lib, so delete the implib
  rm -f "${_pkg}"/lib/*.dll.a
  # Stick to the name expected by everyone
  mv -f "${_pkg}"/lib/libzlibstatic.a "${_pkg}"/lib/libz.a

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/*.h "${_DST}/include"
  cp -f -p "${_pkg}"/lib/*.a     "${_DST}/lib/"
  cp -f -p ChangeLog             "${_DST}/ChangeLog.txt"
  cp -f -p README                "${_DST}/COPYING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
