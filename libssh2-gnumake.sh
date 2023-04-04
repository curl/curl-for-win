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

  CFLAGS=''
  CPPFLAGS=''
  LIBS=''

  if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
    [ "${_CPU}" = 'x64' ] && export ARCH='w64'
    [ "${_CPU}" = 'x86' ] && export ARCH='w32'
    # ARM64 support missing from upstream.

    CPPFLAGS="${CPPFLAGS} -DHAVE_STRTOLL"
    CPPFLAGS="${CPPFLAGS} -DHAVE_DECL_SECUREZEROMEMORY=1 -DLIBSSH2_CLEAR_MEMORY -D_FILE_OFFSET_BITS=64"
  else
    CFLAGS="${CFLAGS} -O3"
  fi

  if [ -n "${_ZLIB}" ]; then
    if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
      export ZLIB_PATH="../../${_ZLIB}/${_PP}/include"
      export WITH_ZLIB=1
    else
      export ZLIB_PATH="../../${_ZLIB}/${_PP}"
    fi
  fi

  if [ -n "${_OPENSSL}" ]; then
    export OPENSSL_PATH="../../${_OPENSSL}/${_PP}"
    if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
      CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR"
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        CPPFLAGS="${CPPFLAGS} -DNOCRYPT"  # Necessary due to the settings in win32/libss2_config.h
      elif [ "${_OPENSSL}" = 'libressl' ]; then
        CPPFLAGS="${CPPFLAGS} -DNOCRYPT"  # Avoid warnings
      fi
    fi
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      # for DLL
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        LIBS="${LIBS} -Wl,-Bdynamic -lpthread -Wl,-Bstatic"
      else
        LIBS="${LIBS} -lpthread"
      fi
    fi
  elif [ -d ../wolfssl ]; then
    if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
      CPPFLAGS="${CPPFLAGS} -DLIBSSH2_WOLFSSL"
      CPPFLAGS="${CPPFLAGS} -I../../wolfssl/${_PP}/include"
      export OPENSSL_INCLUDE="../../wolfssl/${_PP}/include/wolfssl"
    else
      export WOLFSSL_PATH="../../wolfssl/${_PP}"
    fi
  elif [ -d ../mbedtls ] && [ "${LIBSSH2_VER_}" != '1.10.0' ]; then
    export MBEDTLS_PATH="../../mbedtls/${_PP}"
  elif [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
    export WITH_WINCNG=1
  fi

  if [ "${LIBSSH2_VER_}" = '1.10.0' ]; then
    export CROSSPREFIX="${_BINUTILS_PREFIX}"  # for windres
    export LIBSSH2_CC="${CC}"
    export LIBSSH2_RC="${RC}"
    export LIBSSH2_AR="${AR}"
    export LIBSSH2_RANLIB="${RANLIB}"
    export LIBSSH2_DLL_A_SUFFIX='.dll'
    export LIBSSH2_CFLAG_EXTRAS="${_CFLAGS_GLOBAL} ${CFLAGS} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS}"
    export LIBSSH2_LDFLAG_EXTRAS="${_LDFLAGS_GLOBAL} ${LIBS}"
    export LIBSSH2_RCFLAG_EXTRAS="${_RCFLAGS_GLOBAL}"
  else
    export CC="${_CC_GLOBAL}"
    export CFLAGS="${_CFLAGS_GLOBAL} ${CFLAGS}"
    export CPPFLAGS="${_CPPFLAGS_GLOBAL} ${CPPFLAGS}"
    export LDFLAGS="${_LDFLAGS_GLOBAL}"
    export LIBS="${_LIBS_GLOBAL} ${LIBS}"
    export RCFLAGS="${_RCFLAGS_GLOBAL}"
  fi

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    "${_MAKE}" --jobs="${_JOBS}" --directory=win32 distclean
  fi
  "${_MAKE}" --jobs="${_JOBS}" --directory=win32 lib  # dll
# "${_MAKE}" --jobs="${_JOBS}" --directory=win32 test

  # Install manually

  mkdir -p "${_PP}/include"
  mkdir -p "${_PP}/lib"

  cp -f -p ./include/*.h "${_PP}/include/"
  cp -f -p ./win32/*.a   "${_PP}/lib/"

  . ../libssh2-pkg.sh
)
