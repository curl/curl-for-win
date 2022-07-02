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

  # Build

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  # To fix this bizarre error when executing 'make':
  #   configure.ac:39: error: version mismatch.  This is Automake 1.16.4,
  #   configure.ac:39: but the definition used by this AM_INIT_AUTOMAKE
  #   configure.ac:39: comes from Automake 1.16.3.  You should recreate
  #   configure.ac:39: aclocal.m4 with aclocal and run automake again.
  #   [...]
  # Requires: autopoint (sometimes offered by the gettext package)
  [ -f 'Makefile' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  (
    mkdir "${_BLDDIR}"
    cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --disable-rpath \
      --enable-static \
      --disable-shared \
      --disable-server \
      --enable-scram-sha1 \
      --enable-scram-sha256 \
      --disable-obsolete \
      --disable-valgrind-tests --silent
  )

  make --directory="${_BLDDIR}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete .pc and .la files
  rm -r -f "${_pkg}"/lib/pkgconfig
  rm -f    "${_pkg}"/lib/*.la

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/lib/*.a
  touch -c -r "${_ref}" "${_pkg}"/include/*.h

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/lib/*.a     "${_DST}/lib/"
  cp -f -p "${_pkg}"/include/*.h "${_DST}/include/"
  cp -f -p NEWS                  "${_DST}/NEWS.txt"
  cp -f -p AUTHORS               "${_DST}/AUTHORS.txt"
  cp -f -p COPYING               "${_DST}/COPYING.txt"
  cp -f -p README                "${_DST}/README.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
