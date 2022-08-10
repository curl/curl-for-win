#!/bin/sh

# FIXME (upstream):
# - enabling SCP results in error:
#   ../src/wolfscp.c:2277:49: error: incomplete definition of type 'struct dirent'
# - configure warnings:
#   ../configure: line 14942: unistd.h: command not found
#   ../configure: line 14956: unistd.h: command not found
# - Tries to build examples/tests despite passing --disable-examples.
# - Tries and fails to use threading (apparently pthreads) with no
#   documented option to control it.
#   Seems to be happening in examples/tests, which is always enabled.
# - Several compiler warnings, some generic, some Windows-specific,
#   some MSVC-specific.

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  # configure is broken and does not disable examples when passing option
  # --disable-examples. Also, there is no option to disable tests. Yet they
  # fail unfixably. Disable them using brute force:
  echo > examples/include.am
  echo > tests/include.am

  [ -f 'configure' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  if [ -d ../wolfssl ]; then
    options="${options} --with-wolfssl=${_TOP}/wolfssl/${_PP}"
    LIBS="${LIBS} -lws2_32"
    if [ -n "${_ZLIB}" ]; then
      LDFLAGS="${LDFLAGS} -L${_TOP}/${_ZLIB}/${_PP}/lib"
      LIBS="${LIBS} -lz"
    fi
  fi

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --enable-static \
      --disable-shared \
      --disable-scp \
      --enable-sftp \
      --disable-term \
      --disable-examples --silent
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

  mkdir -p "${_DST}/include/wolfssh"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/wolfssh/*.h  "${_DST}/include/wolfssh"
  cp -f -p "${_pkg}"/lib/*.a              "${_DST}/lib/"
  cp -f -p ChangeLog.md                   "${_DST}/"
  cp -f -p README.md                      "${_DST}/"
  cp -f -p LICENSING                      "${_DST}/LICENSING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
