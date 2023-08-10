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

  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} ${LIBSSH2_CPPFLAGS}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export BLD_DIR="${_BLDDIR}"

  if [ -n "${_ZLIB}" ]; then
    export ZLIB_PATH="../${_ZLIB}/${_PP}"
  fi

  if [ -n "${_OPENSSL}" ]; then
    export OPENSSL_PATH="../${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      # for DLL
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        LIBS="${LIBS} -Wl,-Bdynamic -lpthread -Wl,-Bstatic"
      else
        LIBS="${LIBS} -lpthread"
      fi
    fi
  elif [ -d ../wolfssl ]; then
    export WOLFSSL_PATH="../wolfssl/${_PP}"
  elif [ -d ../mbedtls ]; then
    export MBEDTLS_PATH="../mbedtls/${_PP}"
  fi

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    "${_MAKE}" --jobs="${_JOBS}" --makefile=Makefile.mk distclean
  fi
  "${_MAKE}" --jobs="${_JOBS}" --makefile=Makefile.mk lib  # dyn
# "${_MAKE}" --jobs="${_JOBS}" --makefile=Makefile.mk test example

  # Install manually

  mkdir -p "${_PP}/include"
  mkdir -p "${_PP}/lib"

  cp -f -p include/*.h       "${_PP}/include/"
  cp -f -p "${BLD_DIR}"/*.a  "${_PP}/lib/"

  . ../libssh2-pkg.sh
)
