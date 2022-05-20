#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  # Build

  export ARCH
  [ "${_CPU}" = 'x86' ] && ARCH='w32'
  [ "${_CPU}" = 'x64' ] && ARCH='w64'

  export LIBSSH2_CFLAG_EXTRAS='-fno-ident -DHAVE_STRTOI64 -DLIBSSH2_DH_GEX_NEW=1 -DHAVE_DECL_SECUREZEROMEMORY=1 -DHAVE_EVP_AES_128_CTR=1'
  [ "${_CPU}" = 'x86' ] && LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"

  export ZLIB_PATH=../../zlib/pkg/usr/local
  export WITH_ZLIB=1

  if [ -d ../libressl ]; then
    export OPENSSL_PATH=../../libressl
    LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -DNOCRYPT"
  fi
  if [ -d ../openssl ]; then
    export OPENSSL_PATH=../../openssl
    LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -DOPENSSL_SUPPRESS_DEPRECATED"
  fi
  if [ -z "${OPENSSL_PATH:-}" ]; then
    export WITH_WINCNG=1
  fi

  export CROSSPREFIX="${_CCPREFIX}"

  if [ "${CC}" = 'mingw-clang' ]; then
    export LIBSSH2_CC="clang${_CCSUFFIX}"
    if [ "${_OS}" != 'win' ]; then
      LIBSSH2_CFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${LIBSSH2_CFLAG_EXTRAS}"
    fi
  # LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -Xclang -cfguard"
  fi

  ${_MAKE} --jobs 2 --directory win32 clean
  ${_MAKE} --jobs 2 --directory win32 lib

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives win32/*.a

  touch -c -r "${_ref}" win32/*.a

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
  cp -f -p include/*.h   "${_DST}/include/"
  cp -f -p win32/*.a     "${_DST}/lib/"
  cp -f -p NEWS          "${_DST}/NEWS.txt"
  cp -f -p COPYING       "${_DST}/COPYING.txt"
  cp -f -p README        "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES "${_DST}/RELEASE-NOTES.txt"

  [ -d ../zlib ] && cp -f -p ../zlib/README "${_DST}/COPYING-zlib.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
