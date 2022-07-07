#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# https://boringssl.googlesource.com/boringssl/
# https://bugs.chromium.org/p/boringssl/issues/list

# FIXME: x64 mingw-w64 pthread ucrt static linking bug -> requires llvm-mingw

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -ffile-prefix-map=$(pwd)="
  _CFLAGS="${_CFLAGS} -lpthread -lws2_32"  # libs for tests

  options=''

  [ "${_CPU}" = 'x86' ] && cpu='x86'
  [ "${_CPU}" = 'x64' ] && cpu='x86_64'
  if [ "${_CPU}" = 'a64' ]; then
    cpu='ARM64'; options="${options} -DOPENSSL_NO_ASM=1"  # FIXME
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${options} \
    "-DCMAKE_SYSTEM_PROCESSOR=${cpu}" \
    '-DBUILD_SHARED_LIBS=0' \
    '-DOPENSSL_SMALL=0' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}" \
    "-DCMAKE_CXX_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # List files created
  find "${_pkg}"

  # Make steps for determinism

  readonly _ref='README.md'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib"
  cp -f -p LICENSE                       "${_DST}/LICENSE.txt"
  cp -f -p README.md                     "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
