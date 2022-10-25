#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"; [ -n "${2:-}" ] && _NAM="$2"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  options=''
  CFLAGS=''

  # FIXME: As of zlib 1.2.13 and zlib-ng 2.0.6, their CMakeLists.txt prevents
  #        passing custom RCFLAGS to the RC command. Use our wrapper as a
  #        workaround. PRs:
  #        https://github.com/madler/zlib/pull/677
  #        https://github.com/zlib-ng/zlib-ng/pull/1318 [MERGED]
  [ -n "${_RC_WRAPPER}" ] && export RC="${_RC_WRAPPER}"

  if [ "${_NAM}" = 'zlibng' ]; then
    options="${options} -DBUILD_SHARED_LIBS=OFF"
    options="${options} -DZLIB_COMPAT=ON"
    options="${options} -DZLIB_ENABLE_TESTS=OFF"
  else
    # clang 15+ workaround for: https://github.com/madler/zlib/issues/633
    if [ "${_CC}" = 'clang' ] && \
       [ "${_CCVER}" != '14' ]; then
      CFLAGS="${CFLAGS} -Wno-deprecated-non-prototype"
    fi
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS_GLOBAL} ${CFLAGS} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  ls -l "${_PP}"/lib/*.a

  # Delete the implib, if any
  rm -f "${_PP}"/lib/*.dll.a
  if [ "${_NAM}" = 'zlib' ]; then
    # Stick to the name expected by everyone
    mv -f "${_PP}"/lib/libzlibstatic.a "${_PP}"/lib/libz.a
  fi

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  if [ "${_NAM}" = 'zlibng' ]; then
    readonly _ref='README.md'
  else
    readonly _ref='ChangeLog'
  fi

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/*.h "${_DST}/include"
  cp -f -p "${_PP}"/lib/*.a     "${_DST}/lib/"
  if [ "${_NAM}" = 'zlibng' ]; then
    cp -f -p LICENSE.md           "${_DST}/"
    cp -f -p README.md            "${_DST}/"
  else
    cp -f -p ChangeLog            "${_DST}/ChangeLog.txt"
    cp -f -p README               "${_DST}/COPYING.txt"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
