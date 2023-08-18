#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
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

  if [ "${_NAM}" = 'zlibng' ]; then
    options="${options} -DBUILD_SHARED_LIBS=OFF"
    options="${options} -DZLIB_COMPAT=ON"
    options="${options} -DZLIB_ENABLE_TESTS=OFF"
  else
    # Unset this to use an alternative workaround which does not need our
    # _RC_WRAPPER trickery:
    zlib_use_rc_wrapper='1'

    if [ "${zlib_use_rc_wrapper}" = '1' ]; then
      # FIXME (upstream): zlib v1.3 prevents passing custom RCFLAGS to
      #                   the RC command. Use our wrapper as a workaround.
      #                   PR: https://github.com/madler/zlib/pull/677
      [ -n "${_RC_WRAPPER}" ] && export RC="${_RC_WRAPPER}"
    fi
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    "-DCMAKE_RC_FLAGS=${_RCFLAGS_GLOBAL}" \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${CFLAGS} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  if [ "${_NAM}" = 'zlib' ] && \
     [ "${zlib_use_rc_wrapper}" != '1' ]; then
    # Building shared lib has issues compiling resources:
    #   PR: https://github.com/madler/zlib/pull/677
    # Workaround to build static only and install manually:
    make --directory="${_BLDDIR}" --jobs="${_JOBS}" zlibstatic

    mkdir -p "${_PP}/include"
    mkdir -p "${_PP}/lib"

    cp -f -p ./zlib.h             "${_PP}/include/"
    cp -f -p "${_BLDDIR}"/zconf.h "${_PP}/include/"
    cp -f -p "${_BLDDIR}"/*.a     "${_PP}/lib/"
  else
    make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"
  fi

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
  _DST="$(realpath _pkg)"; rm -r -f "${_DST}"

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
