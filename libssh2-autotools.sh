#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-autotools//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIRS:?}" "${_BLDDIR:?}"

  [ -f 'configure' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} ${_CFLAGS_GLOBAL_AUTOTOOLS}"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} ${LIBSSH2_CPPFLAGS}"
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL_AUTOTOOLS}"
  export LIBS=''

  # NOTE: root path with spaces breaks all values with '${_TOP}'. But,
  #       autotools breaks on spaces anyway, so we leave it like that.

  if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then
    options+=' --with-libz'
    # These seem to work better than --with-libz-prefix=:
    CPPFLAGS+=" -I${_TOP}/${_ZLIB}/${_PP}/include"
    LDFLAGS+=" -L${_TOP}/${_ZLIB}/${_PP}/lib"
  else
    options+=' --without-libz'
  fi

  if [ -n "${_OPENSSL}" ] && [ -d "../${_OPENSSL}/${_PP}" ]; then
    options+=" --with-crypto=openssl --with-libssl-prefix=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OS}" = 'win' ]; then
      if [ "${_OPENSSL}" = 'boringssl' ] || [ "${_OPENSSL}" = 'awslc' ]; then
        # for DLL
        if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
          LDFLAGS+=' -Wl,-Bdynamic,-lpthread,-Bstatic'
        else
          LDFLAGS+=' -Wl,-Bstatic,-lpthread,-Bdynamic'
        fi
      elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'libressl' ] || [ "${_OPENSSL}" = 'openssl' ]; then
        LIBS+=' -lbcrypt'
      fi
    fi
  elif [[ "${_DEPS}" = *'wolfssl'* ]] && [ -d "../wolfssl/${_PP}" ]; then
    options+=" --with-crypto=wolfssl --with-libwolfssl-prefix=${_TOP}/wolfssl/${_PP}"
    LDFLAGS+=" -L${_TOP}/wolfssl/${_PP}/lib"
  elif [[ "${_DEPS}" = *'mbedtls'* ]] && [ -d "../mbedtls/${_PP}" ]; then
    options+=" --with-crypto=mbedtls --with-libmbedcrypto-prefix=${_TOP}/mbedtls/${_PP}"
    LDFLAGS+=" -L${_TOP}/mbedtls/${_PP}/lib"
  elif [ "${_OS}" = 'win' ]; then
    options+=' --with-crypto=wincng'
  fi

  if [ "${LIBSSH2_VER_}" != '1.11.0' ]; then
    options+=' --disable-deprecated'
  fi

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --disable-rpath \
      --disable-debug \
      --disable-hidden-symbols \
      --enable-static \
      --disable-shared \
      --disable-examples-build
  )

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIRS}" # >/dev/null # V=1

  # Delete .pc and .la files
  rm -r -f "${_PPS}"/lib/pkgconfig
  rm -f    "${_PPS}"/lib/*.la

  . ../libssh2-pkg.sh
)
