#!/bin/sh -x

# Copyright 2014-2017 Viktor Szakats <https://github.com/vszakats>
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

   # Build

   find . -name '*.o'   -type f -delete
   find . -name '*.a'   -type f -delete
   find . -name '*.lo'  -type f -delete
   find . -name '*.la'  -type f -delete
   find . -name '*.lai' -type f -delete
   find . -name '*.Plo' -type f -delete
   find . -name '*.pc'  -type f -delete
   find . -name '*.dll' -type f -delete
   find . -name '*.exe' -type f -delete

   export CC="${_CCPREFIX}gcc -static-libgcc"
   export LDFLAGS="-m${_cpu}"
   export CFLAGS="${LDFLAGS} -fno-ident"
   [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"
   ./configure \
      --disable-dependency-tracking \
      --disable-silent-rules \
      '--prefix=/usr/local' \
      --silent
#  make clean > /dev/null
   make install "DESTDIR=$(pwd)/pkg" > /dev/null

   # DESTDIR= + --prefix=
   _pkg='pkg/usr/local'

   # Make steps for determinism

   readonly _ref='NEWS'

   "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ${_pkg}/lib/*.a
   "${_CCPREFIX}strip" -p -s ${_pkg}/bin/*.exe

   ../_peclean.py "${_ref}" "${_pkg}/bin/*.exe"

   ../_sign.sh "${_pkg}/bin/*.exe"

   touch -c -r "${_ref}" ${_pkg}/bin/*.exe
   touch -c -r "${_ref}" ${_pkg}/lib/*.a
   touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
   touch -c -r "${_ref}" ${_pkg}/include/*.h

   # Tests

   ${_pkg}/bin/idn.exe -V

   # Create package

   _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/include"
   mkdir -p "${_DST}/lib/pkgconfig"

   cp -f -p ${_pkg}/bin/*.exe          "${_DST}/"
   cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
   cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
   cp -f -p ${_pkg}/include/*.h        "${_DST}/include/"
   cp -f -p NEWS                       "${_DST}/NEWS.txt"
   cp -f -p AUTHORS                    "${_DST}/AUTHORS.txt"
   cp -f -p COPYING                    "${_DST}/COPYING.txt"
   cp -f -p README                     "${_DST}/README.txt"

   unix2dos -k "${_DST}"/*.txt

#  ../_pack.sh "$(pwd)/${_ref}"
#  ../_ul.sh
)
