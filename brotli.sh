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
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  unset CC

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -DMINGW_HAS_SECURE_API"

  # shellcheck disable=SC2086
  cmake . ${_CMAKE_GLOBAL} \
    '-DBROTLI_DISABLE_TESTS=ON' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg="pkg${_PREFIX}"

  # Remove '-static' suffixes from static lib names to make these behave
  # like most other projects do.

  for fn in "${_pkg}"/lib/*-static.a; do
    mv "${fn}" "$(echo "${fn}" | sed 's|-static||')"
  done

  # Delete implibs

  rm -f "${_pkg}"/lib/*.dll.a

  # libcurl only uses the decoding functionality

  rm -f "${_pkg}"/include/encode.h
  rm -f "${_pkg}"/lib/libbrotlienc.a
  rm -f "${_pkg}"/lib/pkgconfig/libbrotlienc.pc

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='docs/brotli.1'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/brotli/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"
  mkdir -p "${_DST}/lib"
  mkdir -p "${_DST}/include/brotli"

  cp -f -p "${_pkg}"/include/brotli/*.h "${_DST}/include/brotli/"
  cp -f -p "${_pkg}"/lib/*.a            "${_DST}/lib/"
  cp -f -p README.md                    "${_DST}/"
  cp -f -p LICENSE                      "${_DST}/LICENSE.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
