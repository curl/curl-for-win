#!/bin/sh -x

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
   options="PREFIX=${_CCPREFIX} IMPLIB=dummy"
   export LDFLAGS="-m${_cpu} -static-libgcc"
   export LOC="${LDFLAGS} -fno-ident -D_LARGEFILE64_SOURCE=1 -D_LFS64_LARGEFILE=1"
   [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && LOC="${LOC} -fno-asynchronous-unwind-tables"

   # shellcheck disable=SC2086
   make -f win32/makefile.gcc ${options} clean #> /dev/null
   # shellcheck disable=SC2086
   make -f win32/makefile.gcc ${options} install #> /dev/null
)
