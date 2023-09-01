#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"; [ -n "${2:-}" ] && _NAM="$2"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  options=''

  if [ "${_NAM}" = 'zlibng' ]; then
    options="${options} -DZLIB_COMPAT=ON"
    options="${options} -DZLIB_ENABLE_TESTS=OFF"
  fi

  # `BUILD_SHARED_LIBS=OFF` broken as of zlib v1.3.
  # PR: https://github.com/madler/zlib/pull/347

  # As of zlib v1.3 CMake warns about unused `CMAKE_INSTALL_LIBDIR` variable.
  # This is an upstream bug. zlib is supposed to be obeying this variable.
  # PR: https://github.com/madler/zlib/pull/148 (opened on 2016-06-04)

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    '-DBUILD_SHARED_LIBS=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"

  if [ "${_NAM}" = 'zlib' ]; then
    # zlib's RC compilation is broken as of v1.3 (2023-08-18) with broken CMake
    # option to disable shared libs. `install` wants to build all targets.
    # Workaround: Build static only and install manually.
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

  if [ "${_NAM}" = 'zlib' ] && [ -f "${_PP}"/lib/libzlibstatic.a ]; then
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
  _DST="$(realpath .)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/*.h "${_DST}/include"
  cp -f -p "${_PP}"/lib/*.a     "${_DST}/lib/"
  if [ "${_NAM}" = 'zlibng' ]; then
    cp -f -p LICENSE.md           "${_DST}/"
    cp -f -p README.md            "${_DST}/"
  else
    cp -f -p LICENSE              "${_DST}/LICENSE.txt"
    cp -f -p ChangeLog            "${_DST}/ChangeLog.txt"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
