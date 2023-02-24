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

  CPPFLAGS='-DHAVE_DECL_SECUREZEROMEMORY=1 -D_FILE_OFFSET_BITS=64'
  LDFLAGS=''
  LIBS=''
  options=''

  if [ -n "${_ZLIB}" ]; then
    options="${options} -DENABLE_ZLIB_COMPRESSION=ON"
    options="${options} -DZLIB_ROOT=${_TOP}/${_ZLIB}/${_PP}"
  fi

  if [ -n "${_OPENSSL}"  ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      LIBS="${LIBS} -lpthread"  # to detect HAVE_EVP_AES_128_CTR
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      CPPFLAGS="${CPPFLAGS} -DNOCRYPT"
      LIBS="${LIBS} -lbcrypt"
      LIBS="${LIBS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
    elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      CPPFLAGS="${CPPFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
      LIBS="${LIBS} -lbcrypt"
      LIBS="${LIBS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
    fi
  elif [ -d ../wolfssl ] && false; then
    # UNTESTED. Missing upstream support.
    options="${options} -DCRYPTO_BACKEND=wolfSSL"
    CPPFLAGS="${CPPFLAGS} -I${_TOP}/wolfssl/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L${_TOP}/wolfssl/${_PP}/lib"
    LIBS="${LIBS} -lwolfssl"
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
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${_LIBS_GLOBAL} ${LIBS}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  . ../libssh2-pkg.sh
)
