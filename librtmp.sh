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

_CDO="$(pwd)"

(
   cd "${_NAM}" || exit

   # Build

   export INC=-I../../openssl/include -I../../zlib
   [ "${_CPU}" = 'win32' ] && export XCFLAGS='-m32'
   [ "${_CPU}" = 'win64' ] && export XCFLAGS='-m64'
   export XLDFLAGS="${XCFLAGS} \"-L${_CDO}/openssl\" \"-L${_CDO}/zlib\""
   export LDFLAGS="${XLDFLAGS}"
   export XCFLAGS="${XCFLAGS} -fno-ident"

   find . -name '*.o'   -type f -delete
   find . -name '*.a'   -type f -delete
   find . -name '*.dll' -type f -delete
   find . -name '*.so'  -type f -delete
   find . -name '*.exe' -type f -delete

   mingw32-make SYS=mingw SODEF_yes=

   # Make steps for determinism

   if ls librtmp/*.a > /dev/null 2>&1 ; then strip -p --enable-deterministic-archives -g librtmp/*.a ; fi

   ../_peclean.py './*.exe'
   ../_peclean.py 'librtmp/*.dll'

   readonly _REF='ChangeLog'

   touch -c -r "${_REF}" librtmp/*.exe
   touch -c -r "${_REF}" librtmp/*.dll
   touch -c -r "${_REF}" librtmp/*.a
)
