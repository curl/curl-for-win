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

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3 -Wa,--noexecstack"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  if [ "${_CC}" = 'clang' ]; then
    CFLAGS="${CFLAGS} -Wno-inconsistent-dllimport"
  else
    CFLAGS="${CFLAGS} -Wno-attributes"
  fi

  _win_prefix='C:/Windows/libressl'
  _ssldir="ssl"

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --enable-static \
      --disable-shared \
      --disable-tests \
      "--prefix=${_win_prefix}" \
      "--with-openssldir=${_win_prefix}/${_ssldir}" --silent
  )

  # Ending slash required.
  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}/" >/dev/null # 2>&1

  # LibreSSL does not strip the drive letter
  #   ./libressl/${_PKGDIR}/C:/Windows/libressl
  # Some tools (e.g CMake) become weird when colons appear in
  # a filename, so move results to a sane, standard path:

  mkdir -p "./${_PP}"
  mv "${_PKGDIR}/${_win_prefix}"/* "${_PP}"

  # Delete .pc and .la files
  rm -r -f "${_PP}"/lib/pkgconfig
  rm -f    "${_PP}"/lib/*.la

  # Tests

  # shellcheck disable=SC2043
  for bin in \
    "${_PP}"/bin/openssl.exe \
  ; do
    file "${bin}"
    # Produce 'openssl version -a'-like output without executing the build:
    strings "${bin}" | grep -a -E '^(LibreSSL [0-9]|built on: |compiler: |platform: |[A-Z]+DIR: )' || true
  done

  . ../libressl-pkg.sh
)
