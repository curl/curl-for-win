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

  # Prepare build

  find . -name '*.dll' -delete
  find . -name '*.def' -delete

  # Build

  export ARCH
  [ "${_CPU}" = 'x86' ] && ARCH="w32"
  [ "${_CPU}" = 'x64' ] && ARCH="w64"

  export LIBSSH2_CFLAG_EXTRAS='-fno-ident -DHAVE_STRTOI64 -DLIBSSH2_DH_GEX_NEW=1 -DHAVE_DECL_SECUREZEROMEMORY=1'
  [ "${_CPU}" = 'x86' ] && LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"
  export LIBSSH2_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
  [ "${_CPU}" = 'x64' ] && LIBSSH2_LDFLAG_EXTRAS="${LIBSSH2_LDFLAG_EXTRAS} -Wl,--high-entropy-va -Wl,--image-base,0x152000000"

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    LIBSSH2_LDFLAG_EXTRAS="${LIBSSH2_LDFLAG_EXTRAS} -Wl,-Map,libssh2.map"
  fi

  if [ -d ../zlibng ]; then
    export ZLIB_PATH=../../zlibng/pkg/usr/local
  else
    export ZLIB_PATH=../../zlib/pkg/usr/local
  fi
  export WITH_ZLIB=1
  export LINK_ZLIB_STATIC=1

  [ -d ../openssl ]  && export OPENSSL_PATH=../../openssl
  if [ -n "${OPENSSL_PATH:-}" ]; then
    export OPENSSL_LIBPATH="${OPENSSL_PATH}"
    export OPENSSL_LIBS_DYN='crypto.dll'
  else
    export WITH_WINCNG=1
  fi

  [ "${_CPU}" = 'x64' ] && export LIBSSH2_DLL_SUFFIX=-x64
  export LIBSSH2_DLL_A_SUFFIX=.dll

  export CROSSPREFIX="${_CCPREFIX}"

  if [ "${CC}" = 'mingw-clang' ]; then
    export LIBSSH2_CC="clang${_CCSUFFIX}"
    if [ "${_OS}" != 'win' ]; then
      LIBSSH2_CFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${LIBSSH2_CFLAG_EXTRAS}"
      [ "${_OS}" = 'linux' ] && LIBSSH2_LDFLAG_EXTRAS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${LIBSSH2_LDFLAG_EXTRAS}"
      LIBSSH2_LDFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${LIBSSH2_LDFLAG_EXTRAS}"
    fi
  # LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -Xclang -cfguard"
  # LIBSSH2_LDFLAG_EXTRAS="${LIBSSH2_LDFLAG_EXTRAS} -Xlinker -guard:cf"
  fi

  (
    cd win32
    ${_MAKE} -j 2 clean
    ${_MAKE} -j 2
  )

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives win32/*.a

  ../_peclean.py "${_ref}" win32/*.dll

  ../_sign-code.sh "${_ref}" win32/*.dll

  touch -c -r "${_ref}" win32/*.dll
  touch -c -r "${_ref}" win32/*.def
  touch -c -r "${_ref}" win32/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" win32/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers win32/*.dll | grep -a -E -i "(file format|dll name)"

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"
  mkdir -p "${_DST}/bin"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p include/*.h   "${_DST}/include/"
  cp -f -p win32/*.dll   "${_DST}/bin/"
  cp -f -p win32/*.def   "${_DST}/bin/"
  cp -f -p win32/*.a     "${_DST}/lib/"
  cp -f -p NEWS          "${_DST}/NEWS.txt"
  cp -f -p COPYING       "${_DST}/COPYING.txt"
  cp -f -p README        "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES "${_DST}/RELEASE-NOTES.txt"

  [ -d ../zlibng ]  && cp -f -p ../zlibng/LICENSE.md "${_DST}/COPYING-zlib-ng.md"
  [ -d ../zlib ]    && cp -f -p ../zlib/README       "${_DST}/COPYING-zlib.txt"

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p win32/*.map   "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
