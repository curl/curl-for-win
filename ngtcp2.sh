#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -DNDEBUG"

  options=''

  if [ -d ../openssl-quic ]; then
    options="${options} -DENABLE_OPENSSL=1"
    options="${options} -DOPENSSL_ROOT_DIR=../openssl-quic/${_PP}"
    options="${options} -DOPENSSL_INCLUDE_DIR=../openssl-quic/${_PP}/include"
    # Detection fails due to missing -lws2_32 -lbcrypt options, so force it.
    #   https://github.com/ngtcp2/ngtcp2/pull/481
    options="${options} -DHAVE_SSL_IS_QUIC=1"
  fi

  if [ -d ../nghttp3 ]; then
    options="${options} -DLIBNGHTTP3_LIBRARY=../nghttp3/${_PP}/lib"
    options="${options} -DLIBNGHTTP3_INCLUDE_DIR=../nghttp3/${_PP}/include"
  fi

  options="${options} -DLIBEV_LIBRARY="  # Avoid finding non-cross copies

  # We do not need C++ with ENABLE_LIB_ONLY, so make sure to skip the detection
  # logic and potential detection issues with CMAKE_CXX_COMPILER_WORKS=1. Some
  # success was achieve by adding these instead to the cmake command-line:
  #   ${_CMAKE_CXX_GLOBAL}
  #   "-DCMAKE_CXX_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${_CXXFLAGS_GLOBAL}"
  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    '-DENABLE_STATIC_LIB=1' \
    '-DENABLE_SHARED_LIB=0' \
    '-DCMAKE_CXX_COMPILER_WORKS=1' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Rename static libs so they get found by dependents
  if [ -d ../openssl-quic ]; then
    mv -f "${_pkg}"/lib/libngtcp2_crypto_openssl_static.a "${_pkg}"/lib/libngtcp2_crypto_openssl.a
  fi
  mv -f "${_pkg}"/lib/libngtcp2_static.a "${_pkg}"/lib/libngtcp2.a

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/ngtcp2/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/ngtcp2"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/ngtcp2/*.h "${_DST}/include/ngtcp2/"
  cp -f -p "${_pkg}"/lib/*.a            "${_DST}/lib/"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                      "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README.rst                   "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
