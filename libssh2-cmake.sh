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

  CPPFLAGS=''
  LIBS=''
  options=''

  if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
    # TODO: Also delete all `CPPFLAGS` references when deleting this.
    CPPFLAGS="${CPPFLAGS} -DHAVE_DECL_SECUREZEROMEMORY=1 -D_FILE_OFFSET_BITS=64"
  fi

  if [ -n "${_ZLIB}" ]; then
    options="${options} -DENABLE_ZLIB_COMPRESSION=ON"
    options="${options} -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
    options="${options} -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
  fi

  if [ -n "${_OPENSSL}" ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        LIBS="${LIBS} -lpthread"  # to detect HAVE_EVP_AES_128_CTR
      elif [ "${_OPENSSL}" = 'libressl' ]; then
        LIBS="${LIBS} -lbcrypt"
        LIBS="${LIBS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
      elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'openssl' ]; then
        LIBS="${LIBS} -lbcrypt"
        LIBS="${LIBS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
      fi
    fi
    # Silence useless libssh2 warnings about missing runtime DLLs
    touch \
      "${_TOP}/${_OPENSSL}/${_PP}/crypto.dll" \
      "${_TOP}/${_OPENSSL}/${_PP}/ssl.dll"
  elif [ -d ../wolfssl ]; then
    if [ "${LIBSSH2_VER_}" != '1.10.0' ]; then
      options="${options} -DCRYPTO_BACKEND=wolfSSL"
      options="${options} -DWOLFSSL_LIBRARY=${_TOP}/wolfssl/${_PP}/lib/libwolfssl.a"
      options="${options} -DWOLFSSL_INCLUDE_DIR=${_TOP}/wolfssl/${_PP}/include"
    fi
  elif [ -d ../mbedtls ] && [ "${LIBSSH2_VER_}" != '1.10.0' ]; then
    options="${options} -DCRYPTO_BACKEND=mbedTLS"
    options="${options} -DMBEDCRYPTO_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedcrypto.a"
    options="${options} -DMBEDTLS_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedtls.a"
    options="${options} -DMBEDX509_LIBRARY=${_TOP}/mbedtls/${_PP}/lib/libmbedx509.a"
    options="${options} -DMBEDTLS_INCLUDE_DIR=${_TOP}/mbedtls/${_PP}/include"
  else
    options="${options} -DCRYPTO_BACKEND=WinCNG"
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DBUILD_EXAMPLES=OFF' \
    '-DBUILD_TESTING=OFF' \
    '-DENABLE_DEBUG_LOGGING=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${LIBS}"  # --debug-trycompile

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  . ../libssh2-pkg.sh
)
