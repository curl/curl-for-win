#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md

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

  rm -r -f pkg CMakeFiles CMakeCache.txt CTestTestfile.cmake cmake_install.cmake

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  unset CC

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -fno-ident -D_LARGEFILE64_SOURCE=1 -D_LFS64_LARGEFILE=1"

  # shellcheck disable=SC2086
  cmake . ${_CMAKE_GLOBAL} \
    '-DCMAKE_RC_FLAGS=-DGCC_WINDRES' \
    "-DCMAKE_C_FLAGS=${_CFLAGS}" \
    "-DCMAKE_EXE_LINKER_FLAGS=${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}" \
    "-DCMAKE_SHARED_LINKER_FLAGS=${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg="pkg${_PREFIX}"

  ls -l "${_pkg}"/lib/*.a

  # We need the static lib, so delete the implib
  rm -f "${_pkg}"/lib/*.dll.a
  # Stick to the name expected by everyone
  mv -f "${_pkg}"/lib/libzlibstatic.a "${_pkg}"/lib/libz.a

  # curl Makefile.m32 assumes the headers and lib to be in the
  # same directory.
  cp -f -p "${_pkg}"/include/*.h "${_pkg}/"
  cp -f -p "${_pkg}"/lib/libz.a  "${_pkg}/"

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

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
