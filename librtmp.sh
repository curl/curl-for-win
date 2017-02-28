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

_cdo="$(pwd)"

(
  cd "${_NAM}" || exit 0

  # Build

  find . -name '*.o'   -type f -delete
  find . -name '*.a'   -type f -delete
  find . -name '*.dll' -type f -delete
  find . -name '*.so'  -type f -delete
  find . -name '*.exe' -type f -delete

  export INC='-I../../openssl/include -I../../zlib'
  export XCFLAGS="-m${_cpu}"
  export XLDFLAGS="${XCFLAGS} \"-L${_cdo}/openssl\" \"-L${_cdo}/zlib\" -static-libgcc -Wl,--nxcompat -Wl,--dynamicbase"
  [ "${_cpu}" = '64' ] && [ "${_CCVER}" -ge '0500' ] && XLDFLAGS="${XLDFLAGS} -Wl,--high-entropy-va -Wl,--image-base,0x153000000"
  export LDFLAGS="${XLDFLAGS}"
  export XCFLAGS="${XCFLAGS} -fno-ident"
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && XCFLAGS="${XCFLAGS} -fno-asynchronous-unwind-tables"

  export CROSS_COMPILE="${_CCPREFIX}"

  make SYS=mingw SODEF_yes=

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g librtmp/*.a

  ../_peclean.py "${_ref}" './*.exe'
  ../_peclean.py "${_ref}" 'librtmp/*.dll'

  ../_sign.sh './*.exe'
  ../_sign.sh 'librtmp/*.dll'

  touch -c -r "${_ref}" librtmp/*.exe
  touch -c -r "${_ref}" librtmp/*.dll
  touch -c -r "${_ref}" librtmp/*.a

# ../_pack.sh "$(pwd)/${_ref}"
# ../_ul.sh
)
