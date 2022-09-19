#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md
#
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  # We may need this in the future if an "Automake version mismatch" occurs:
# [ -f 'configure' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  if [ -d ../libiconv ]; then
    options="${options} --with-libiconv-prefix=${_TOP}/libiconv/${_PP}"
  fi
  if [ -d ../libunistring ]; then
    options="${options} --with-libunistring-prefix=${_TOP}/libunistring/${_PP}"
  fi

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --disable-rpath \
      --enable-static \
      --disable-shared \
      --disable-doc --silent
  )

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete .pc and .la files
  rm -r -f "${_pkg}"/lib/pkgconfig
  rm -f    "${_pkg}"/lib/*.la

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/*.h "${_DST}/include/"
  cp -f -p "${_pkg}"/lib/*.a     "${_DST}/lib/"
  cp -f -p NEWS                  "${_DST}/NEWS.txt"
  cp -f -p AUTHORS               "${_DST}/AUTHORS.txt"
  cp -f -p COPYING               "${_DST}/COPYING.txt"
  cp -f -p README                "${_DST}/README.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
