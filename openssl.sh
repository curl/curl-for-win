#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_CPU="$2"

(
   cd "${_NAM}" || exit 0

   readonly _REF='CHANGES'

   # Build

   find . -name '*.o'   -type f -delete
   find . -name '*.a'   -type f -delete
   find . -name '*.dll' -type f -delete
   find . -name '*.exe' -type f -delete

   [ "${_CPU}" = '32' ] && OPTIONS='mingw'
   [ "${_CPU}" = '64' ] && OPTIONS='mingw64'
   if [ "${_BRANCH#*lto*}" != "${_BRANCH}" ] ; then
      # Create a fixed seed based on the timestamp of the OpenSSL source package.
      OPTIONS="${OPTIONS} -flto -ffat-lto-objects -frandom-seed=$(stat -c %Y "${_REF}")"
      # mingw64 build (as of mingw 5.2.0) will fail without the `no-asm` option.
      [ "${_CPU}" = '64' ] && OPTIONS="${OPTIONS} no-asm"
   fi
   if [ "$(echo "${OPENSSL_VER_}" | cut -c -5)" = '1.0.2' ] ; then
      [ "${_CPU}" = '32' ] && export SHARED_RCFLAGS='--target=pe-i386'
      [ "${_CPU}" = '64' ] && export SHARED_RCFLAGS='--target=pe-x86-64'
      OPTIONS="${OPTIONS} -m${_CPU} no-ssl2 -static-libgcc"
   else
      OPTIONS="${OPTIONS} no-filenames"
   fi
   # Requires mingw 5.0 or upper
   [ "${_CPU}" = '64' ] && OPTIONS="${OPTIONS} -Wl,--high-entropy-va"
   [ "$(echo "${OPENSSL_VER_}" | cut -c -9)" = '1.1.0-pre' ] && OPTIONS="${OPTIONS} --unified"
   [ "$(echo "${OPENSSL_VER_}" | cut -c -9)" = '1.1.0-dev' ] && OPTIONS="${OPTIONS} --unified"

   # shellcheck disable=SC2086
   ./Configure ${OPTIONS} shared \
      -fno-ident \
      -Wl,--nxcompat -Wl,--dynamicbase \
      no-unit-test no-ssl3 no-rc5 no-idea no-dso '--prefix=/usr/local'
   [ "$(echo "${OPENSSL_VER_}" | cut -c -5)" = '1.1.0' ] || make depend
   make

   # Make steps for determinism

   strip -p --enable-deterministic-archives -g ./*.a
   strip -p -s apps/openssl.exe
   strip -p -s apps/*.dll

   ../_peclean.py "${_REF}" 'apps/openssl.exe'
   ../_peclean.py "${_REF}" 'apps/*.dll'
   if ls engines/*.dll > /dev/null 2>&1 ; then
      ../_peclean.py "${_REF}" 'engines/*.dll'
   fi

   touch -c -r "${_REF}" apps/openssl.exe
   touch -c -r "${_REF}" apps/*.dll
   touch -c -r "${_REF}" include/openssl/*.h
   touch -c -r "${_REF}" ./*.a
   if ls engines/*.dll > /dev/null 2>&1 ; then
      touch -c -r "${_REF}" engines/*.dll
   fi

   # Tests

   apps/openssl.exe version
   apps/openssl.exe ciphers

   objdump -x apps/openssl.exe | grep -E -i "(file format|dll name)"
   objdump -x apps/*.dll       | grep -E -i "(file format|dll name)"

   # Create package

   _BAS="${_NAM}-${_VER}-win${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/include/openssl"
   mkdir -p "${_DST}/lib"

   if ls engines/*.dll > /dev/null 2>&1 ; then
      mkdir -p "${_DST}/engines"
      cp -f -p engines/*.dll    "${_DST}/engines/"
   fi

   cp -f -p apps/openssl.cnf    "${_DST}/"
   cp -f -p apps/openssl.exe    "${_DST}/"
   cp -f -p apps/*.dll          "${_DST}/"
   cp -f -p include/openssl/*.h "${_DST}/include/openssl/"
   cp -f -p ms/applink.c        "${_DST}/include/openssl/"
   cp -f -p ./*.a               "${_DST}/lib/"
   cp -f -p CHANGES             "${_DST}/CHANGES.txt"
   cp -f -p LICENSE             "${_DST}/LICENSE.txt"
   cp -f -p README              "${_DST}/README.txt"
   cp -f -p FAQ                 "${_DST}/FAQ.txt"
   cp -f -p NEWS                "${_DST}/NEWS.txt"

   unix2dos -k "${_DST}"/*.txt

   ../_pack.sh "$(pwd)/${_REF}"
   ../_ul.sh
)
