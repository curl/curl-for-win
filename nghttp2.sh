#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  # Build

  rm -r -f "${_PKGDIR}" CMakeFiles CMakeCache.txt CTestTestfile.cmake cmake_install.cmake

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  unset CC

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -DNDEBUG"

  # We do not need C++ with ENABLE_LIB_ONLY, so make sure to skip the detection
  # logic and potential detection issues with CMAKE_CXX_COMPILER_WORKS=1
  # shellcheck disable=SC2086
  cmake . ${_CMAKE_GLOBAL} \
    '-DENABLE_LIB_ONLY=1' \
    '-DENABLE_STATIC_LIB=1' \
    '-DENABLE_SHARED_LIB=0' \
    '-DCMAKE_CXX_COMPILER_WORKS=1' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/nghttp2/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/nghttp2"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/nghttp2/*.h "${_DST}/include/nghttp2/"
  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib/"
  cp -f -p ChangeLog                     "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                       "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                       "${_DST}/COPYING.txt"
  cp -f -p README.rst                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
