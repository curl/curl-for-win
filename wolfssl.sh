#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  [ -f 'configure' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  if [ -n "${_ZLIB}" ]; then
    options="${options} --with-libz=${_TOP}/${_ZLIB}/${_PP}"
  fi

  # for libssh2
  options="${options} --enable-keygen"
  options="${options} --enable-aesctr"
  options="${options} --enable-aesgcm-stream"

  # Required for curl
  options="${options} --enable-curl"

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --enable-static \
      --disable-shared \
      --enable-quic \
      --enable-session-ticket \
      --enable-earlydata \
      --enable-psk \
      --enable-harden \
      --enable-altcertchains \
      --enable-reproducible-build \
      --disable-benchmark \
      --disable-crypttests \
      --disable-examples --silent
  )

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1

  # Delete .pc and .la files
  rm -r -f "${_PP}"/lib/pkgconfig
  rm -f    "${_PP}"/lib/*.la

  . ../wolfssl-pkg.sh
)
