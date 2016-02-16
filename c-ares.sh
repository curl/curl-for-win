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

   # Build

   export CARES_CFLAG_EXTRAS="-m${_CPU} -fno-ident"
   export CARES_LDFLAG_EXTRAS="-m${_CPU} -static-libgcc -Wl,--nxcompat -Wl,--dynamicbase"
   [ "${_CPU}" = '64' ] && CARES_LDFLAG_EXTRAS="${CARES_LDFLAG_EXTRAS} -Wl,--high-entropy-va"

   mingw32-make -f Makefile.m32 clean
   mingw32-make -f Makefile.m32
   mingw32-make -f Makefile.m32 demos

   # Make steps for determinism

   readonly _REF='NEWS'

   strip -p --enable-deterministic-archives -g *.a

   ../_peclean.py "${_REF}" '*.exe'

   touch -c -r "${_REF}" *.a
   touch -c -r "${_REF}" *.exe

   # Create package

   _BAS="${_NAM}-${_VER}-win${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}"

   cp -f -p ares.h        "${_DST}/"
   cp -f -p ares_build.h  "${_DST}/"
   cp -f -p ares_rules.h  "${_DST}/"
   cp -f -p *.a           "${_DST}/"
   cp -f -p *.exe         "${_DST}/"
   cp -f -p *.pdf         "${_DST}/"
   cp -f -p README.md     "${_DST}/"
   cp -f -p NEWS          "${_DST}/NEWS.txt"
   cp -f -p RELEASE-NOTES "${_DST}/RELEASE-NOTES.txt"

   unix2dos -k "${_DST}"/*.md
   unix2dos -k "${_DST}"/*.txt

#  ../_pack.sh "$(pwd)/${_REF}"
#  ../_ul.sh
)
