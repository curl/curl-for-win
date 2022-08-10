#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

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

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --enable-static \
      --disable-shared \
      --enable-curl \
      --enable-quic \
      --enable-session-ticket \
      --enable-earlydata \
      --enable-psk \
      --enable-harden \
      --enable-altcertchains \
      --disable-examples \
      --disable-benchmark \
      --enable-reproducible-build --silent
  )

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete .pc and .la files
  rm -r -f "${_pkg}"/lib/pkgconfig
  rm -f    "${_pkg}"/lib/*.la

  # Make steps for determinism

  readonly _ref='ChangeLog.md'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/wolfssl/openssl"
  mkdir -p "${_DST}/include/wolfssl/wolfcrypt"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/wolfssl/openssl/*.h    "${_DST}/include/wolfssl/openssl"
  cp -f -p "${_pkg}"/include/wolfssl/wolfcrypt/*.h  "${_DST}/include/wolfssl/wolfcrypt"
  cp -f -p "${_pkg}"/include/wolfssl/*.h            "${_DST}/include/wolfssl"
  cp -f -p "${_pkg}"/lib/*.a                        "${_DST}/lib/"
  cp -f -p ChangeLog.md                             "${_DST}/ChangeLog.md"
  cp -f -p README.md                                "${_DST}/"
  cp -f -p COPYING                                  "${_DST}/COPYING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
