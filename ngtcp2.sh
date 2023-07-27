#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  CPPFLAGS='-DNDEBUG'
  LDFLAGS=''
  LIBS=''
  options=''

  if [ "${_OPENSSL}" = 'boringssl' ]; then
    options="${options} -DENABLE_OPENSSL=OFF"
    options="${options} -DENABLE_BORINGSSL=ON"
    options="${options} -DBORINGSSL_INCLUDE_DIR=${_TOP}/${_OPENSSL}/${_PP}/include"
    options="${options} -DBORINGSSL_LIBRARIES=${_TOP}/${_OPENSSL}/${_PP}/lib/libcrypto.a;${_TOP}/${_OPENSSL}/${_PP}/lib/libssl.a;-lpthread;-lws2_32"
    CPPFLAGS="${CPPFLAGS} -DNOCRYPT"
  elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'libressl' ]; then
    options="${options} -DENABLE_OPENSSL=ON"
    options="${options} -DOPENSSL_ROOT_DIR=../${_OPENSSL}/${_PP}"
    # FIXME: This is not enough for picky ld linker (with gcc)
    if [ -n "${_ZLIB}" ]; then  # required by OpenSSL built with zlib
      LDFLAGS="${LDFLAGS} -L${_TOP}/${_ZLIB}/${_PP}/lib"
      LIBS="${LIBS} -lz"
    fi
  elif [ -d ../wolfssl ]; then
    options="${options} -DENABLE_WOLFSSL=ON"
    options="${options} -DWOLFSSL_INCLUDE_DIR=../wolfssl/${_PP}/include"
    options="${options} -DWOLFSSL_LIBRARY=../wolfssl/${_PP}/lib/libwolfssl.a"
    LIBS="${LIBS} -lws2_32"
    if [ -n "${_ZLIB}" ]; then  # required by wolfSSL
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/${_ZLIB}/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/${_ZLIB}/${_PP}/lib"
      LIBS="${LIBS} -lz"
    fi
  fi

  if [ -d ../nghttp3 ]; then
    options="${options} -DLIBNGHTTP3_INCLUDE_DIR=../nghttp3/${_PP}/include"
    options="${options} -DLIBNGHTTP3_LIBRARY=../nghttp3/${_PP}/lib"
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${options} \
    '-DENABLE_STATIC_LIB=ON' \
    '-DENABLE_SHARED_LIB=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${_LIBS_GLOBAL} ${LIBS}" \
    "-DCMAKE_CXX_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${_LIBS_GLOBAL} ${LIBS} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/ngtcp2/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(realpath _pkg)"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/ngtcp2"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/ngtcp2/*.h "${_DST}/include/ngtcp2/"
  cp -f -p "${_PP}"/lib/*.a            "${_DST}/lib/"
  cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                     "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                     "${_DST}/COPYING.txt"
  cp -f -p README.rst                  "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
