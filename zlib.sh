#!/bin/sh -ex

# Copyright 2017 Viktor Szakats <https://github.com/vszakats>
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

  find . -name '*.o' -type f -delete
  find . -name '*.a' -type f -delete

  # Set IMPLIB to something that is not found by dependents in order to force
  # linking the static lib instead.
  options="PREFIX=${_CCPREFIX} IMPLIB=dummy.a"
  export LDFLAGS="-m${_cpu} -static-libgcc -Wl,--nxcompat -Wl,--dynamicbase"
  [ "${_cpu}" = '64' ] && [ "${_CCVER}" -ge '0500' ] && LDFLAGS="${LDFLAGS} -Wl,--high-entropy-va -Wl,--image-base,0x155000000"
  export LOC="${LDFLAGS} -fno-ident -D_LARGEFILE64_SOURCE=1 -D_LFS64_LARGEFILE=1"
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && LOC="${LOC} -fno-asynchronous-unwind-tables"

  # shellcheck disable=SC2086
  make -f win32/Makefile.gcc ${options} clean > /dev/null
  # shellcheck disable=SC2086
  make -f win32/Makefile.gcc ${options} > /dev/null

  ls -l ./*.dll
  ls -l ./*.a

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ./*.a
  "${_CCPREFIX}strip" -p -s ./*.dll

  ../_peclean.py "${_ref}" '*.dll'

  ../_sign.sh '*.dll'

  touch -c -r "${_ref}" ./*.dll
  touch -c -r "${_ref}" ./*.a

  # Tests

  "${_CCPREFIX}objdump" -x ./*.dll | grep -E -i "(file format|dll name)"

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"

  cp -f -p ./*.h     "${_DST}/"
  cp -f -p ./*.a     "${_DST}/"
  cp -f -p ChangeLog "${_DST}/ChangeLog.txt"
  cp -f -p README    "${_DST}/README.txt"

  unix2dos -k "${_DST}"/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
