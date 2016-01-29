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

   export MAKE=mingw32-make

   [ "${_CPU}" = 'win32' ] && export SHARED_RCFLAGS='-F pe-i386'
   [ "${_CPU}" = 'win64' ] && export SHARED_RCFLAGS='-F pe-x86-64'

   find . -name '*.o'   -type f -delete
   find . -name '*.a'   -type f -delete
   find . -name '*.exe' -type f -delete

   [ "${_CPU}" = 'win32' ] && ./Configure mingw   shared no-unit-test no-ssl2 no-ssl3 no-rc5 no-idea no-dso '--prefix=/usr/local'
   # Disable asm in 64-bit builds. It makes linking the static libs fail in LTO mode:
   #   C:\Users\...\AppData\Local\Temp\ccUO3sBD.s: Assembler messages:
   #   C:\Users\...\AppData\Local\Temp\ccUO3sBD.s:23710: Error: operand type mismatch for `div'
   #   lto-wrapper.exe: fatal error: gcc.exe returned 1 exit status
   #   compilation terminated.
   #   C:/mingw/bin/../lib/gcc/x86_64-w64-mingw32/5.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: lto-wrapper failed
   #   collect2.exe: error: ld returned 1 exit status
   [ "${_CPU}" = 'win64' ] && ./Configure mingw64 shared no-unit-test no-ssl2 no-ssl3 no-rc5 no-idea no-dso no-asm '--prefix=/usr/local'
   mingw32-make depend
   mingw32-make

   # Make steps for determinism

   if ls ./*.a > /dev/null 2>&1 ; then strip -p --enable-deterministic-archives -g ./*.a ; fi

   # Strip debug info

   strip -p -s apps/openssl.exe
   strip -p -s apps/*.dll

   ../_peclean.py 'apps/openssl.exe'
   ../_peclean.py 'apps/*.dll'
   if ls engines/*.dll > /dev/null 2>&1 ; then
      ../_peclean.py 'engines/*.dll'
   fi

   readonly _REF='CHANGES'

   touch -c -r "${_REF}" apps/openssl.exe
   touch -c -r "${_REF}" apps/*.dll
   touch -c -r "${_REF}" include/openssl/*.h
   touch -c -r "${_REF}" ./*.a
   if ls engines/*.dll > /dev/null 2>&1 ; then
      touch -c -r "${_REF}" engines/*.dll
   fi

   # Test run

   apps/openssl.exe version
   apps/openssl.exe ciphers

   # Create package

   _BAS="${_NAM}-${_VER}-${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/include/openssl"
   mkdir -p "${_DST}/lib"

   if ls engines/*.dll > /dev/null 2>&1 ; then
      mkdir -p "${_DST}/engines"
      cp -f -p engines/*.dll    "${_DST}/engines/"
   fi

   cp -f -p apps/openssl.exe    "${_DST}/"
   cp -f -p apps/*.dll          "${_DST}/"
   cp -f -p apps/openssl.cnf    "${_DST}/openssl.cfg"
   cp -f -p include/openssl/*.h "${_DST}/include/openssl/"
   cp -f -p ms/applink.c        "${_DST}/include/openssl/"
   cp -f -p CHANGES             "${_DST}/CHANGES.txt"
   cp -f -p LICENSE             "${_DST}/LICENSE.txt"
   cp -f -p README              "${_DST}/README.txt"
   cp -f -p FAQ                 "${_DST}/FAQ.txt"
   cp -f -p NEWS                "${_DST}/NEWS.txt"

   if ls ./*.a > /dev/null 2>&1 ; then cp -f -p ./*.a "${_DST}/lib" ; fi

   unix2dos -k "${_DST}"/*.txt

   ../_pack.sh "$(pwd)/${_REF}"
   ../_ul.sh
)
