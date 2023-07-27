#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  LIBS=''
  options=''

  if [ -n "${_ZLIB}" ]; then
    options="${options} -DENABLE_ZLIB_COMPRESSION=ON"
    options="${options} -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
    options="${options} -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
  fi

  if [ -n "${_OPENSSL}" ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      # for DLL
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        LIBS="${LIBS} -Wl,-Bdynamic -lpthread -Wl,-Bstatic"
      else
        LIBS="${LIBS} -lpthread"
      fi
    fi
    # Silence useless libssh2 warnings about missing runtime DLLs
    touch \
      "${_TOP}/${_OPENSSL}/${_PP}/crypto.dll" \
      "${_TOP}/${_OPENSSL}/${_PP}/ssl.dll"
  elif [ -d ../wolfssl ]; then
    options="${options} -DCRYPTO_BACKEND=wolfSSL"
    options="${options} -DWOLFSSL_INCLUDE_DIR=${_TOP}/wolfssl/${_PP}/include"
    options="${options} -DWOLFSSL_LIBRARY=${_TOP}/wolfssl/${_PP}/lib/libwolfssl.a"
  elif [ -d ../mbedtls ]; then
    options="${options} -DCRYPTO_BACKEND=mbedTLS"
    options="${options} -DMBEDTLS_INCLUDE_DIR=${_TOP}/mbedtls/${_PP}/include"
    options="${options} -DMBEDCRYPTO_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedcrypto.a"
    # Necessary for detection only:
    options="${options} -DMBEDTLS_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedtls.a"
    options="${options} -DMBEDX509_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedx509.a"
  else
    options="${options} -DCRYPTO_BACKEND=WinCNG"
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    '-DCMAKE_UNITY_BUILD=ON' \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DBUILD_EXAMPLES=OFF' \
    '-DBUILD_TESTING=OFF' \
    '-DENABLE_DEBUG_LOGGING=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${LIBS}"  # --debug-trycompile

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  . ../libssh2-pkg.sh
)
