#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -DNDEBUG"

  options=''

  # Experimental. Not necessary for curl.
  # Apps do not build without adding more dependencies.
  if false; then

    # Prevent auto-detecting OS-native libs
    options="${options} -DLIBEVENT_OPENSSL_LIBRARY=OFF"
    options="${options} -DJANSSON_LIBRARY=OFF"
    options="${options} -DJEMALLOC_LIBRARY=OFF"

    if [ -d ../zlib ]; then
      options="${options} -DZLIB_LIBRARY=${_TOP}/zlib/${_PP}/lib/libz.a"
      options="${options} -DZLIB_INCLUDE_DIR=${_TOP}/zlib/${_PP}/include"

      # Strange hack necessary otherwise it does not find its own header and lib
      _CFLAGS="${_CFLAGS} -I${_TOP}/nghttp2/lib/includes"
      _CFLAGS="${_CFLAGS} -L${_TOP}/nghttp2/${_BLDDIR}/lib"
    fi

    if [ -d ../openssl ]; then
      options="${options} -DOPENSSL_ROOT_DIR=../openssl/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=../openssl/${_PP}/include"
    elif [ -d ../openssl-quic ]; then
      options="${options} -DOPENSSL_ROOT_DIR=../openssl-quic/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=../openssl-quic/${_PP}/include"
    fi

    if [ -d ../nghttp3 ] && [ -d ../ngtcp2 ] && [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
      options="${options} -DLIBNGHTTP3_LIBRARY=../nghttp3/${_PP}/lib"
      options="${options} -DLIBNGHTTP3_INCLUDE_DIR=../nghttp3/${_PP}/include"
      _CFLAGS="${_CFLAGS} -DNGHTTP3_STATICLIB"

      options="${options} -DLIBNGTCP2_LIBRARY=../ngtcp2/${_PP}/lib/libngtcp2.a"
      options="${options} -DLIBNGTCP2_INCLUDE_DIR=../ngtcp2/${_PP}/include"
      options="${options} -DLIBNGTCP2_CRYPTO_OPENSSL_LIBRARY=../ngtcp2/${_PP}/lib/libngtcp2_crypto_openssl.a"
      options="${options} -DLIBNGTCP2_CRYPTO_OPENSSL_INCLUDE_DIR=../ngtcp2/${_PP}/include"
      _CFLAGS="${_CFLAGS} -DNGTCP2_STATICLIB"

      options="${options} -DENABLE_HTTP3=ON"
    fi
  else
    options="${options} -DENABLE_LIB_ONLY=ON"
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${options} \
    '-DENABLE_STATIC_LIB=ON' \
    '-DENABLE_SHARED_LIB=OFF' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}" \
    "-DCMAKE_CXX_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/nghttp2/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/nghttp2"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/nghttp2/*.h "${_DST}/include/nghttp2/"
  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib/"
  cp -f -p ChangeLog                     "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                       "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                       "${_DST}/COPYING.txt"
  cp -f -p README.rst                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
