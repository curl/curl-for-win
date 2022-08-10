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

  CPPFLAGS='-DHAVE_DECL_SECUREZEROMEMORY=1 -D_FILE_OFFSET_BITS=64'
  LDFLAGS=''
  LIBS=''
  options=''

  if [ -n "${_ZLIB}" ]; then
    options="${options} -DENABLE_ZLIB_COMPRESSION=ON"
    options="${options} -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
    options="${options} -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
  fi

  if [ -n "${_OPENSSL}"  ]; then
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/${_OPENSSL}/${_PP}/include"
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      LIBS="${LIBS} -lpthread"  # to detect HAVE_EVP_AES_128_CTR
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      CPPFLAGS="${CPPFLAGS} -DNOCRYPT"
      LIBS="${LIBS} -lbcrypt"
      LIBS="${LIBS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
    elif [ "${_OPENSSL}" = 'openssl-quic' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      CPPFLAGS="${CPPFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
      LIBS="${LIBS} -lbcrypt"
      LIBS="${LIBS} -lws2_32"  # to detect HAVE_EVP_AES_128_CTR
    fi
  elif [ -d ../wolfssl ] && false; then
    # UNTESTED. Missing upstream support.
    options="${options} -DCRYPTO_BACKEND=WolfSSL"
    CPPFLAGS="${CPPFLAGS} -I${_TOP}/wolfssl/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L${_TOP}/wolfssl/${_PP}/lib"
    LIBS="${LIBS} -lwolfssl"
  elif [ -d ../mbedtls ]; then
    if false; then
      # Compile errors as of mbedTLS 3.2.1 + libssh 1.10.0
      options="${options} -DCRYPTO_BACKEND=mbedTLS"
      options="${options} -DMBEDCRYPTO_LIBRARY=${_TOP}/mbedtls/${_PP}/lib"
      options="${options} -DMBEDTLS_LIBRARY=${_TOP}/mbedtls/${_PP}/lib"
      options="${options} -DMBEDX509_LIBRARY=${_TOP}/mbedtls/${_PP}/lib"
      options="${options} -DMBEDTLS_INCLUDE_DIR=${_TOP}/mbedtls/${_PP}/include"
    fi
  else
    options="${options} -DCRYPTO_BACKEND=WinCNG"
  fi

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DBUILD_EXAMPLES=OFF' \
    '-DBUILD_TESTING=OFF' \
    '-DENABLE_DEBUG_LOGGING=OFF' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${_LIBS_GLOBAL} ${LIBS}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

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
