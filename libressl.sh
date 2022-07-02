#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

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
    mkdir "${_BLDDIR}"
    cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --enable-static \
      --disable-shared \
      --disable-tests \
      "--prefix=${_win_prefix}" \
      "--with-openssldir=${_win_prefix}/${_ssldir}" --silent
  )

  # Ending slash required.
  make --directory="${_BLDDIR}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}/" >/dev/null # 2>&1

  # LibreSSL does not strip the drive letter
  #   ./libressl/${_PKGDIR}/C:/Windows/libressl
  # Some tools (e.g CMake) become weird when colons appear in
  # a filename, so move results to a sane, standard path:

  _pkg="${_PP}"  # DESTDIR= + _PREFIX
  mkdir -p "./${_pkg}"
  mv "${_PKGDIR}/${_win_prefix}"/* "${_pkg}"

  # Delete .pc and .la files
  rm -r -f "${_pkg}"/lib/pkgconfig
  rm -f    "${_pkg}"/lib/*.la

  # List files created

  find "${_pkg}" | grep -a -v -F '/share/' | sort

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/lib/*.a
  touch -c -r "${_ref}" "${_pkg}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_pkg}"/include/*.h

  # Tests

  # shellcheck disable=SC2043
  for bin in \
    "${_pkg}"/bin/openssl.exe \
  ; do
    file "${bin}"
    # Produce 'openssl version -a'-like output without executing the build:
    strings "${bin}" | grep -a -E '^(LibreSSL [0-9]|built on: |compiler: |platform: |[A-Z]+DIR: )' || true
  done

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib"
  cp -f -p "${_pkg}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_pkg}"/include/*.h         "${_DST}/include/"
  cp -f -p ChangeLog                     "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                       "${_DST}/COPYING.txt"
  cp -f -p README.md                     "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
