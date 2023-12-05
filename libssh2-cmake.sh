#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  [ "${CW_DEV_INCREMENTAL:-}" != '1' ] && rm -r -f "${_PKGDIRS:?}" "${_BLDDIR:?}"

  LIBS=''
  options=''

  if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then
    options+=' -DENABLE_ZLIB_COMPRESSION=ON'
    options+=" -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
    options+=" -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
  fi

  if [ -n "${_OPENSSL}" ] && [ -d "../${_OPENSSL}/${_PP}" ]; then
    options+=' -DCRYPTO_BACKEND=OpenSSL'
    options+=" -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ] || [ "${_OPENSSL}" = 'awslc' ]; then
      # for DLL
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        LIBS+=' -Wl,-Bdynamic -lpthread -Wl,-Bstatic'
      else
        LIBS+=' -lpthread'
      fi
    fi
    if [ "${_OS}" = 'win' ]; then
      # Silence useless libssh2 warnings about missing runtime DLLs
      touch \
        "${_TOP}/${_OPENSSL}/${_PP}/crypto.dll" \
        "${_TOP}/${_OPENSSL}/${_PP}/ssl.dll"
    fi
  elif [[ "${_DEPS}" = *'wolfssl'* ]] && [ -d "../wolfssl/${_PP}" ]; then
    options+=' -DCRYPTO_BACKEND=wolfSSL'
    options+=" -DWOLFSSL_INCLUDE_DIR=${_TOP}/wolfssl/${_PP}/include"
    options+=" -DWOLFSSL_LIBRARY=${_TOP}/wolfssl/${_PP}/lib/libwolfssl.a"
  elif [[ "${_DEPS}" = *'mbedtls'* ]] && [ -d "../mbedtls/${_PP}" ]; then
    options+=' -DCRYPTO_BACKEND=mbedTLS'
    options+=" -DMBEDTLS_INCLUDE_DIR=${_TOP}/mbedtls/${_PP}/include"
    options+=" -DMBEDCRYPTO_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedcrypto.a"
    if [ "${LIBSSH2_VER_}" = '1.11.0' ]; then
      # Necessary for detection only:
      options+=" -DMBEDTLS_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedtls.a"
      options+=" -DMBEDX509_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedx509.a"
    fi
  elif [ "${_OS}" = 'win' ]; then
    options+=' -DCRYPTO_BACKEND=WinCNG'
  fi

  if [ "${LIBSSH2_VER_}" != '1.11.0' ]; then
    options+=' -DLIBSSH2_NO_DEPRECATED=ON'
  fi

  if [ "${CW_DEV_CROSSMAKE_REPRO:-}" != '1' ] && \
     [[ "${_CONFIG}" != *'nounity'* ]]; then
    options+=' -DCMAKE_UNITY_BUILD=ON'
  fi

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ] || [ ! -d "${_BLDDIR}" ]; then
    # shellcheck disable=SC2086
    cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
      '-DBUILD_SHARED_LIBS=OFF' \
      '-DBUILD_EXAMPLES=OFF' \
      '-DBUILD_TESTING=OFF' \
      '-DENABLE_DEBUG_LOGGING=OFF' \
      "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${LIBSSH2_CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LIBS}"  # --debug-trycompile
  fi

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIRS}"

  # Delete .pc files
  rm -r -f "${_PPS}"/lib/pkgconfig

  . ../libssh2-pkg.sh
)
