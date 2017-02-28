#!/bin/sh -ex

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
  cd "${_NAM}" || exit 0

  # Build

  export CARES_CFLAG_EXTRAS="-m${_cpu} -fno-ident"
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && CARES_CFLAG_EXTRAS="${CARES_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"
  export CARES_LDFLAG_EXTRAS="-m${_cpu} -static-libgcc -Wl,--nxcompat -Wl,--dynamicbase"
  [ "${_cpu}" = '64' ] && [ "${_CCVER}" -ge '0500' ] && CARES_LDFLAG_EXTRAS="${CARES_LDFLAG_EXTRAS} -Wl,--high-entropy-va -Wl,--image-base,0x154000000"

  export CROSSPREFIX="${_CCPREFIX}"

  ${_MAKE} -f Makefile.m32 clean
  ${_MAKE} -f Makefile.m32
  ${_MAKE} -f Makefile.m32 demos

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ./*.a

  ../_peclean.py "${_ref}" '*.exe'

  ../_sign.sh '*.exe'

  touch -c -r "${_ref}" ./*.a
  touch -c -r "${_ref}" ./*.exe

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"

  cp -f -p ares.h        "${_DST}/"
  cp -f -p ares_build.h  "${_DST}/"
  cp -f -p ares_rules.h  "${_DST}/"
  cp -f -p ./*.a         "${_DST}/"
  cp -f -p ./*.exe       "${_DST}/"
  cp -f -p ./*.pdf       "${_DST}/"
  cp -f -p README.md     "${_DST}/"
  cp -f -p NEWS          "${_DST}/NEWS.txt"
  cp -f -p RELEASE-NOTES "${_DST}/RELEASE-NOTES.txt"

  unix2dos -k "${_DST}"/*.md
  unix2dos -k "${_DST}"/*.txt

#  ../_pack.sh "$(pwd)/${_ref}"
#  ../_ul.sh
)
