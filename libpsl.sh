#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Issues:
# - does not support CMake, only autotools (with showstoppers) and meson.
# Workaround these by building manually.

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  # Build manually

  [ -f 'suffixes_dafsa.h' ] || python3 'src/psl-make-dafsa' --output-format=cxx+ 'list/public_suffix_list.dat' 'suffixes_dafsa.h'

  mkdir -p "${_BLDDIR}"
  (
    cd "${_BLDDIR}"
    # shellcheck disable=SC2046,SC2086
    ${_CC_GLOBAL} ${_CFLAGS_GLOBAL} ${_CFLAGS_GLOBAL_RAW} ${_CPPFLAGS_GLOBAL} \
      -DENABLE_BUILTIN -DPACKAGE_VERSION="\"${LIBPSL_VER_}\"" \
      -I. -I.. -I../include -c $(find ../src -name '*.c' | sort)
    # shellcheck disable=SC2046
    "${AR}" rcs libpsl.a $(find . -name '*.o' | sort)
  )

  # Install manually

  mkdir -p "${_PP}/include"
  mkdir -p "${_PP}/lib"

  cp -f -p include/libpsl.h "${_PP}/include/"
  cp -f -p "${_BLDDIR}"/*.a "${_PP}/lib/"

  # Make steps for determinism

  readonly _ref='NEWS'

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/*.h "${_DST}/include/"
  cp -f -p "${_PP}"/lib/*.a     "${_DST}/lib/"
  cp -f -p NEWS                 "${_DST}/NEWS.txt"
  cp -f -p AUTHORS              "${_DST}/AUTHORS.txt"
  cp -f -p COPYING              "${_DST}/COPYING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
