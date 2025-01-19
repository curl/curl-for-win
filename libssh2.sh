#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  [ "${CW_DEV_INCREMENTAL:-}" != '1' ] && rm -r -f "${_PKGDIRS:?}" "${_BLDDIR:?}"

  LIBS=''
  options=''

  if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then
    options+=' -DENABLE_ZLIB_COMPRESSION=ON'
    options+=" -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
    options+=" -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
  fi

  if [ -n "${_OPENSSL}" ] && [ -d "../${_OPENSSL}/${_PP}" ]; then
    options+=' -DCRYPTO_BACKEND=OpenSSL'
    options+=" -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ] || [ "${_OPENSSL}" = 'awslc' ]; then
      LIBS+=' -lpthread'
    fi
    if [ "${_OS}" = 'win' ]; then
      # Silence useless libssh2 warning about missing runtime DLL
      touch "${_TOP}/${_OPENSSL}/${_PP}/crypto.dll"
    fi
  elif [ "${_OS}" = 'win' ]; then
    options+=' -DCRYPTO_BACKEND=WinCNG'
  fi

  if [[ "${_CONFIG}" != *'nounity'* ]]; then
    options+=' -DCMAKE_UNITY_BUILD=ON'
  fi

  if [ "${_OS}" != 'win' ]; then
    options+=' -DHIDE_SYMBOLS=OFF'
  fi

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ] || [ ! -d "${_BLDDIR}" ]; then
    # shellcheck disable=SC2086
    cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_EXAMPLES=OFF \
      -DBUILD_TESTING=OFF \
      -DENABLE_DEBUG_LOGGING=OFF \
      -DLIBSSH2_NO_DEPRECATED=ON \
      -DCMAKE_C_FLAGS="${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${LIBSSH2_CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LIBS}"  # --debug-trycompile
  fi

  cmake --build "${_BLDDIR}"
  cmake --install "${_BLDDIR}" --prefix "${_PPS}"

  # Delete .pc files
  rm -r -f "${_PPS}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='NEWS'

  rm -f "${_PPS}"/lib/*.dll.a

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PPS}"/lib/*.a

  touch -c -r "${_ref}" "${_PPS}"/include/*.h
  touch -c -r "${_ref}" "${_PPS}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p "${_PPS}"/include/*.h "${_DST}/include/"
  cp -f -p "${_PPS}"/lib/*.a     "${_DST}/lib/"
  cp -f -p NEWS                  "${_DST}/NEWS.txt"
  cp -f -p COPYING               "${_DST}/COPYING.txt"
  cp -f -p README                "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES         "${_DST}/RELEASE-NOTES.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
