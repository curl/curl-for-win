#!/bin/sh -ex

# Copyright 2014-2019 Viktor Szakats <https://vsz.me/>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_cpu="$2"

(
  cd "${_NAM}" || exit

  # Detect host OS
  case "$(uname)" in
    *_NT*)   os='win';;
    Linux*)  os='linux';;
    Darwin*) os='mac';;
    *BSD)    os='bsd';;
  esac

  # Prepare build

  find . -name '*.dll' -type f -delete
  find . -name '*.def' -type f -delete

  # Build

  export ARCH="w${_cpu}"
  export LIBSSH2_CFLAG_EXTRAS='-fno-ident -DHAVE_STRTOI64 -DLIBSSH2_DH_GEX_NEW=1 -DHAVE_DECL_SECUREZEROMEMORY=1'
  [ "${_cpu}" = '32' ] && LIBSSH2_CFLAG_EXTRAS="${LIBSSH2_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"
  export LIBSSH2_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
  [ "${_cpu}" = '64' ] && LIBSSH2_LDFLAG_EXTRAS="${LIBSSH2_LDFLAG_EXTRAS} -Wl,--high-entropy-va -Wl,--image-base,0x152000000"

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    LIBSSH2_LDFLAG_EXTRAS="${LIBSSH2_LDFLAG_EXTRAS} -Wl,-Map,libssh2.map"
  fi

  export ZLIB_PATH=../../zlib/pkg/usr/local
  export WITH_ZLIB=1
  export LINK_ZLIB_STATIC=1

  [ -d ../openssl ]  && export OPENSSL_PATH=../../openssl
  if [ -n "${OPENSSL_PATH}" ]; then
#   export LINK_OPENSSL_STATIC=yes; export OPENSSL_LIBS_STAT='crypto ssl'
    export OPENSSL_LIBPATH="${OPENSSL_PATH}"
    export OPENSSL_LIBS_DYN='crypto.dll ssl.dll'
  else
    export WITH_WINCNG=1
  fi

  if [ "${_cpu}" = '64' ]; then
    export LIBSSH2_DLL_SUFFIX=-x64
  fi
  export LIBSSH2_DLL_A_SUFFIX=.dll

  export CROSSPREFIX="${_CCPREFIX}"

  if [ "${CC}" = 'mingw-clang' ]; then
    export LIBSSH2_CC="clang${_CCSUFFIX}"
    if [ "${os}" != 'win' ]; then
      LIBSSH2_CFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${LIBSSH2_CFLAG_EXTRAS}"
      [ "${os}" = 'linux' ] && LIBSSH2_LDFLAG_EXTRAS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${LIBSSH2_LDFLAG_EXTRAS}"
      LIBSSH2_LDFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${LIBSSH2_LDFLAG_EXTRAS}"
    fi
  fi

  (
    cd win32 || exit
    ${_MAKE} -j 2 clean
    ${_MAKE} -j 2
  )

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g win32/*.a

  ../_peclean.py "${_ref}" win32/*.dll

  ../_sign.sh "${_ref}" win32/*.dll

  touch -c -r "${_ref}" win32/*.dll
  touch -c -r "${_ref}" win32/*.a

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" win32/*.map
    touch -c -r "${_ref}" win32/*.def
  fi

  # Tests

  "${_CCPREFIX}objdump" -x win32/*.dll | grep -E -i "(file format|dll name)"

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"
  mkdir -p "${_DST}/bin"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p include/*.h   "${_DST}/include/"
  cp -f -p win32/*.dll   "${_DST}/bin/"
  cp -f -p win32/*.a     "${_DST}/lib/"
  cp -f -p NEWS          "${_DST}/NEWS.txt"
  cp -f -p COPYING       "${_DST}/COPYING.txt"
  cp -f -p README        "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES "${_DST}/RELEASE-NOTES.txt"

  [ -d ../openssl ]  && cp -f -p ../openssl/LICENSE "${_DST}/LICENSE-openssl.txt"

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    cp -f -p win32/*.map   "${_DST}/bin/"
    cp -f -p win32/*.def   "${_DST}/bin/"
  fi

  unix2dos -q -k "${_DST}"/*.txt
  unix2dos -q -k "${_DST}"/docs/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
