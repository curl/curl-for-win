#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -DHAVE_DECL_SECUREZEROMEMORY=1 -D_FILE_OFFSET_BITS=64"
  _LDFLAGS=''

  options=''

  if [ -d ../zlib ]; then
    options="${options} -DENABLE_ZLIB_COMPRESSION=ON"
    options="${options} -DZLIB_LIBRARY=${_TOP}/zlib/${_PP}/lib/libz.a"
    options="${options} -DZLIB_INCLUDE_DIR=${_TOP}/zlib/${_PP}/include"
  fi

  if [ -d ../libressl ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/libressl/${_PP}"
    options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/libressl/${_PP}/include"
    _CFLAGS="${_CFLAGS} -DNOCRYPT"
    _LDFLAGS="${_LDFLAGS} -lbcrypt"
    _LDFLAGS="${_LDFLAGS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
  elif [ -d ../boringssl ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/boringssl/${_PP}"
    options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/boringssl/${_PP}/include"
    _LDFLAGS="${_LDFLAGS} -lpthread"  # to detect HAVE_EVP_AES_128_CTR
  elif [ -d ../openssl-quic ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/openssl-quic/${_PP}"
    options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/openssl-quic/${_PP}/include"
    _CFLAGS="${_CFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
    _LDFLAGS="${_LDFLAGS} -lbcrypt"
    _LDFLAGS="${_LDFLAGS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
  elif [ -d ../openssl ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/openssl/${_PP}"
    options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/openssl/${_PP}/include"
    _CFLAGS="${_CFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
    _LDFLAGS="${_LDFLAGS} -lbcrypt"
    _LDFLAGS="${_LDFLAGS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
  else
    options="${options} -DCRYPTO_BACKEND=WinCNG"
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DBUILD_EXAMPLES=OFF' \
    '-DBUILD_TESTING=OFF' \
    '-DENABLE_DEBUG_LOGGING=OFF' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${_LDFLAGS}"

  make --directory="${_BLDDIR}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Delete .pc files
  rm -r -f "${_pkg}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p "${_pkg}"/include/*.h "${_DST}/include/"
  cp -f -p "${_pkg}"/lib/*.a     "${_DST}/lib/"
  cp -f -p NEWS                  "${_DST}/NEWS.txt"
  cp -f -p COPYING               "${_DST}/COPYING.txt"
  cp -f -p README                "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES         "${_DST}/RELEASE-NOTES.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
