#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _CPU
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_CPU="$2"

(
   cd "${_NAM}" || exit

   # Build

   export ZLIB_PATH=../../zlib
   export OPENSSL_PATH=../../openssl
   export OPENSSL_LIBPATH="${OPENSSL_PATH}"
   export OPENSSL_LIBS_DYN='crypto.dll ssl.dll'
   [ "${_CPU}" = 'win32' ] && export ARCH=w32
   [ "${_CPU}" = 'win64' ] && export ARCH=w64
   export LIBSSH2_CFLAG_EXTRAS='-fno-ident'
   export LIBSSH2_LDFLAG_EXTRAS='-static-libgcc'

   (
      cd win32 || exit
      mingw32-make clean
      mingw32-make
   )

   # Make steps for determinism

   if ls win32/*.a > /dev/null 2>&1 ; then strip -p --enable-deterministic-archives -g win32/*.a ; fi

   ../_peclean.py 'win32/*.dll'

   readonly _REF='NEWS'

   touch -c -r "${_REF}" win32/*.dll
   touch -c -r "${_REF}" win32/*.a

   # Create package

   _BAS="${_NAM}-${_VER}-${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/docs"
   mkdir -p "${_DST}/include"
   mkdir -p "${_DST}/lib"
   mkdir -p "${_DST}/bin"

   for file in docs/* ; do
      if [ -f "${file}" ] && echo "${file}" | grep -v '\.' > /dev/null 2>&1 ; then
         cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
   done
   cp -f -p include/*.h         "${_DST}/include/"
   cp -f -p NEWS                "${_DST}/NEWS.txt"
   cp -f -p COPYING             "${_DST}/COPYING.txt"
   cp -f -p README              "${_DST}/README.txt"
   cp -f -p RELEASE-NOTES       "${_DST}/RELEASE-NOTES.txt"
   cp -f -p win32/*.dll         "${_DST}/bin/"

   cp -f -p ../openssl/LICENSE  "${_DST}/LICENSE-openssl.txt"

   if ls win32/*.a > /dev/null 2>&1 ; then cp -f -p win32/*.a "${_DST}/lib" ; fi

   unix2dos -k "${_DST}"/*.txt
   unix2dos -k "${_DST}"/docs/*.txt

   ../_pack.sh "$(pwd)/${_REF}"
   ../_ul.sh
)
