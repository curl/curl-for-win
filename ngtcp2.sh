#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIRS:?}" "${_BLDDIR:?}"

  CPPFLAGS=''
  LDFLAGS=''
  LIBS=''
  options=''

  if [[ "${_CONFIG}" != *'debug'* ]]; then
    CPPFLAGS+=' -DNDEBUG'
  fi

  # Avoid finding unnecessary system (Homebrew) package. This avoids log noise and
  # prevents building examples, which may fail for reasons or just take extra time.
  options+=' -DLIBEV_INCLUDE_DIR='

  if [ "${_OPENSSL}" = 'boringssl' ]; then
    options+=' -DENABLE_OPENSSL=OFF'
    options+=' -DENABLE_BORINGSSL=ON'
    options+=" -DBORINGSSL_INCLUDE_DIR=${_TOP}/${_OPENSSL}/${_PP}/include"
    options+=" -DBORINGSSL_LIBRARIES=${_TOP}/${_OPENSSL}/${_PP}/lib/libcrypto.a;${_TOP}/${_OPENSSL}/${_PP}/lib/libssl.a;-lpthread"; [ "${_OS}" = 'win' ] && options="${options};-lws2_32"
    CPPFLAGS+=' -DNOCRYPT'
  elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'libressl' ]; then
    options+=' -DENABLE_OPENSSL=ON'
    options+=" -DOPENSSL_ROOT_DIR=../${_OPENSSL}/${_PP}"
    # FIXME: This is not enough for picky ld linker (with gcc)
    if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then  # required by OpenSSL built with zlib
      LDFLAGS+=" -L${_TOP}/${_ZLIB}/${_PP}/lib"
      LIBS+=' -lz'
    fi
  elif [[ "${_DEPS}" = *'wolfssl'* ]] && [ -d "../wolfssl/${_PP}" ]; then
    options+=' -DENABLE_WOLFSSL=ON'
    options+=" -DWOLFSSL_INCLUDE_DIR=../wolfssl/${_PP}/include"
    options+=" -DWOLFSSL_LIBRARY=../wolfssl/${_PP}/lib/libwolfssl.a"
    if [ "${_OS}" = 'win' ]; then
      LIBS+=' -lws2_32'
    fi
    if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then  # required by wolfSSL
      CPPFLAGS+=" -I${_TOP}/${_ZLIB}/${_PP}/include"
      LDFLAGS+=" -L${_TOP}/${_ZLIB}/${_PP}/lib"
      LIBS+=' -lz'
    fi
  fi

  if [[ "${_DEPS}" = *'nghttp3'* ]] && [ -d "../nghttp3/${_PP}" ]; then
    options+=" -DLIBNGHTTP3_INCLUDE_DIR=../nghttp3/${_PP}/include"
    options+=" -DLIBNGHTTP3_LIBRARY=../nghttp3/${_PP}/lib"
  fi

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${options} \
    '-DENABLE_STATIC_LIB=ON' \
    '-DENABLE_SHARED_LIB=OFF' \
    '-DBUILD_TESTING=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${LIBS}" \
    "-DCMAKE_CXX_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${LIBS} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIRS}"

  # Delete .pc files
  rm -r -f "${_PPS}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PPS}"/lib/*.a

  touch -c -r "${_ref}" "${_PPS}"/include/ngtcp2/*.h
  touch -c -r "${_ref}" "${_PPS}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/ngtcp2"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PPS}"/include/ngtcp2/*.h "${_DST}/include/ngtcp2/"
  cp -f -p "${_PPS}"/lib/*.a            "${_DST}/lib/"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                      "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README.rst                   "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
