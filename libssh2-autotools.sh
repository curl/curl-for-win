#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-autotools//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  [ -f 'configure' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} ${LIBSSH2_CPPFLAGS}"
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL_AUTOTOOLS}"
  export LIBS="${_LIBS_GLOBAL}"

  # NOTE: root path with spaces breaks all values with '${_TOP}'. But,
  #       autotools breaks on spaces anyway, so we leave it like that.

  if [ -n "${_ZLIB}" ]; then
    options="${options} --with-libz"
    # These seem to work better than --with-libz-prefix=:
    CPPFLAGS="${CPPFLAGS} -I${_TOP}/${_ZLIB}/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L${_TOP}/${_ZLIB}/${_PP}/lib"
  fi

  if [ -n "${_OPENSSL}" ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      # for DLL
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        LDFLAGS="${LDFLAGS} -Wl,-Bdynamic,-lpthread,-Bstatic"
      else
        LDFLAGS="${LDFLAGS} -Wl,-Bstatic,-lpthread,-Bdynamic"
      fi
    elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'libressl' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      LIBS="${LIBS} -lbcrypt"
    fi
  elif [ -d ../wolfssl ]; then
    options="${options} --with-crypto=wolfssl --with-libwolfssl-prefix=${_TOP}/wolfssl/${_PP}"
    LDFLAGS="${LDFLAGS} -L${_TOP}/wolfssl/${_PP}/lib"
  elif [ -d ../mbedtls ]; then
    options="${options} --with-crypto=mbedtls --with-libmbedcrypto-prefix=${_TOP}/mbedtls/${_PP}"
    LDFLAGS="${LDFLAGS} -L${_TOP}/mbedtls/${_PP}/lib"
  else
    options="${options} --with-crypto=wincng"
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
      --disable-examples-build \
      --disable-tests
  )

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1

  # Delete .pc and .la files
  rm -r -f "${_PP}"/lib/pkgconfig
  rm -f    "${_PP}"/lib/*.la

  . ../libssh2-pkg.sh
)
