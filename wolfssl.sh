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

  # Smaller wolfSSL for curl?
  #   https://www.wolfssl.com/how-to-build-a-smaller-wolfssl-library-when-used-with-curl/
  # options="${options} –-enable-opensslextra=x509small"
  # CPPFLAGS="${CPPFLAGS} -DHAVE_CURL"

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

  # Make steps for determinism

  readonly _ref='ChangeLog.md'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(realpath _pkg)"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/wolfssl/openssl"
  mkdir -p "${_DST}/include/wolfssl/wolfcrypt"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/wolfssl/openssl/*.h   "${_DST}/include/wolfssl/openssl"
  cp -f -p "${_PP}"/include/wolfssl/wolfcrypt/*.h "${_DST}/include/wolfssl/wolfcrypt"
  cp -f -p "${_PP}"/include/wolfssl/*.h           "${_DST}/include/wolfssl"
  cp -f -p "${_PP}"/lib/*.a                       "${_DST}/lib/"
  cp -f -p ChangeLog.md                           "${_DST}/"
  cp -f -p README.md                              "${_DST}/"
  cp -f -p COPYING                                "${_DST}/COPYING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
