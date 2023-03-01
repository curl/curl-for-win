#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# EXPERIMENTAL. DO NOT USE FOR PRODUCTION.

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-gnumake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  export ARCH
  [ "${_CPU}" = 'x64' ] && ARCH='w64'
  [ "${_CPU}" = 'x86' ] && ARCH='w32'
  # FIXME: ARM64 support missing from upstream.

  CPPFLAGS='-DHAVE_STRTOI64 -DHAVE_DECL_SECUREZEROMEMORY=1'

  if [ -n "${_ZLIB}" ]; then
    export ZLIB_PATH="../../${_ZLIB}/${_PP}/include"
    export WITH_ZLIB=1
  fi

  if [ -n "${_OPENSSL}"  ]; then
    CPPFLAGS='-DHAVE_EVP_AES_128_CTR'
    export OPENSSL_PATH="../../${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      CPPFLAGS="${CPPFLAGS} -DNOCRYPT"  # Necessary due to the settings in win32/libss2_config.h
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      CPPFLAGS="${CPPFLAGS} -DNOCRYPT"
    fi
  elif [ -d ../wolfssl ]; then
    CPPFLAGS="${CPPFLAGS} -DLIBSSH2_WOLFSSL"
    CPPFLAGS="${CPPFLAGS} -I../../wolfssl/${_PP}/include"
    export OPENSSL_INCLUDE="../../wolfssl/${_PP}/include/wolfssl"
  elif [ -d ../mbedtls ] && [ "${LIBSSH2_VER_}" != '1.10.0' ]; then
    export MBEDTLS_PATH="../../mbedtls/${_PP}"
  else
    export WITH_WINCNG=1
  fi

  export CROSSPREFIX="${_BINUTILS_PREFIX}"  # for windres
  export LIBSSH2_CC="${_CC_GLOBAL}"
  export LIBSSH2_AR="${AR}"
  export LIBSSH2_RANLIB="${RANLIB}"
  export LIBSSH2_CFLAG_EXTRAS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS}"
  export LIBSSH2_LDFLAG_EXTRAS="${_LDFLAGS_GLOBAL}"
  export LIBSSH2_DLL_A_SUFFIX='.dll'

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    make --directory=win32 --jobs="${_JOBS}" distclean
  fi
  make --directory=win32 --jobs="${_JOBS}" lib

  # Install manually

  mkdir -p "${_PP}/include"
  mkdir -p "${_PP}/lib"

  cp -f -p ./include/*.h "${_PP}/include/"
  cp -f -p ./win32/*.a   "${_PP}/lib/"

  . ../libssh2-pkg.sh
)
