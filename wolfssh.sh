#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

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

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

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
  export LDFLAGS="${_LDFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL_AUTOTOOLS}"
  export LIBS="${_LIBS_GLOBAL}"

  if [ -d ../wolfssl ]; then
    options="${options} --with-wolfssl=${_TOP}/wolfssl/${_PP}"
    if [ "${_OS}" = 'win' ]; then
      LIBS="${LIBS} -lws2_32"
    fi
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

  # Delete .pc and .la files
  rm -r -f "${_PP}"/lib/pkgconfig
  rm -f    "${_PP}"/lib/*.la

  # Make steps for determinism

  readonly _ref='ChangeLog.md'

  # shellcheck disable=SC2086
  "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/wolfssh"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/wolfssh/*.h "${_DST}/include/wolfssh"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib/"
  cp -f -p ChangeLog.md                 "${_DST}/"
  cp -f -p README.md                    "${_DST}/"
  cp -f -p LICENSING                    "${_DST}/LICENSING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
