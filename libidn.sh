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

   export CC='gcc -static-libgcc'
   export LDFLAGS="-m${_CPU}"
   export CFLAGS="${LDFLAGS} -fno-ident"
   # Open dummy file descriptor to fix './<script>: line <n>: 0: Bad file descriptor'
   exec 0</dev/null && ./configure --disable-silent-rules '--prefix=/usr/local' --silent
#  exec 0</dev/null && make clean > /dev/null
   exec 0</dev/null && make install "DESTDIR=$(pwd)/pkg" > /dev/null

   # DESTDIR= + --prefix=
   _PKG='pkg/usr/local'

   # Make steps for determinism

   readonly _REF='NEWS'

   strip -p --enable-deterministic-archives -g ${_PKG}/lib/*.a
   strip -p -s ${_PKG}/bin/*.exe

   ../_peclean.py "${_REF}" "${_PKG}/bin/*.exe"

   touch -c -r "${_REF}" ${_PKG}/bin/*.exe
   touch -c -r "${_REF}" ${_PKG}/lib/*.a
   touch -c -r "${_REF}" ${_PKG}/lib/pkgconfig/*.pc
   touch -c -r "${_REF}" ${_PKG}/include/*.h

   # Test run

   ${_PKG}/bin/idn.exe -V

   # Create package

   _BAS="${_NAM}-${_VER}-win${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/include"
   mkdir -p "${_DST}/lib/pkgconfig"

   cp -f -p ${_PKG}/bin/*.exe          "${_DST}/"
   cp -f -p ${_PKG}/lib/*.a            "${_DST}/lib/"
   cp -f -p ${_PKG}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
   cp -f -p ${_PKG}/include/*.h        "${_DST}/include/"
   cp -f -p NEWS                       "${_DST}/NEWS.txt"
   cp -f -p AUTHORS                    "${_DST}/AUTHORS.txt"
   cp -f -p COPYING                    "${_DST}/COPYING.txt"
   cp -f -p README                     "${_DST}/README.txt"

   unix2dos -k "${_DST}"/*.txt
   unix2dos -k "${_DST}"/*.rst

#  ../_pack.sh "$(pwd)/${_REF}"
#  ../_ul.sh
)
