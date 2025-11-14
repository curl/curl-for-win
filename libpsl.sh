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

  # require the psl package, always
  if [ ! -f 'suffixes_dafsa.h' ]; then
    pslfile="../psl/${_PSL}"
    gencsrc='suffixes_dafsa.h'
    python3 'src/psl-make-dafsa' --output-format=cxx+ "${pslfile}" "${gencsrc}"
    # The generator above is including the local PDL filename in the output.
    # libpsl is then making an attempt to load this filename at runtime as-is
    # and loading its content if its timestamp is newer than the embedded one.
    # This is terrible idea in many use cases, including this one, because:
    # - the filename is relative one.
    # - this is loaded on the end user's machine, relative to their current
    #   working directory.
    # - which is by good chance world-writable, and for sure without any
    #   guarantees for protection.
    # - there is no universal location on disks that is not world-writable.
    # - leaks this internal filename into the final binary.
    # Similar case to OpenSSL configurations and CA bundles loaded from
    # world-writable, or arbitrary places on disk (such as PATH), on Windows.
    # To avoid these issues, strip the filename from the output to avoid
    # loading it at runtime:
    sed -i.bak -E 's/(_psl_filename\[\]) *=.+/\1 = "";/g' "${gencsrc}"
    # Verify and abort if the filename is still found in the file
    if grep -a -F "${pslfile}" "${gencsrc}"; then
      echo "! Error: Our local PSL database filename is leaking into the libpsl code."
      exit 1
    fi
    # Fix to use the Windows-native stat function to avoid mingw-w64 v13
    # mapping the POSIX 'stat' one used in libpsl to an intrinsic and breaking
    # interoperability with earlier mingw-w64 versions.
    # This shall really be fixed upstream in libpsl.
    [ "${_OS}" = 'win' ] && echo '#define stat _stati64' >> "${gencsrc}"
  fi

  mkdir -p "${_BLDDIR}"
  (
    cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    find ../src -name '*.c' -print0 | sort -z | xargs -0 -r \
    ${_CC_GLOBAL} ${_CFLAGS_GLOBAL} ${_CFLAGS_GLOBAL_RAW} ${_CPPFLAGS_GLOBAL} \
      -DENABLE_BUILTIN -DPACKAGE_VERSION="\"${LIBPSL_VER_}\"" \
      -I. -I.. -I../include -c   # clang supports `--`, gcc does not
    find . -name '*.o' -print0 | sort -z | xargs -0 -r \
    "${AR}" rcs libpsl.a
  )

  # Install manually

  mkdir -p "${_PP}"/include
  mkdir -p "${_PP}"/lib

  cp -f -p include/libpsl.h "${_PP}"/include/
  cp -f -p "${_BLDDIR}"/*.a "${_PP}"/lib/

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

  mkdir -p "${_DST}"/include
  mkdir -p "${_DST}"/lib

  cp -f -p "${_PP}"/include/*.h "${_DST}"/include/
  cp -f -p "${_PP}"/lib/*.a     "${_DST}"/lib/
  cp -f -p NEWS                 "${_DST}"/NEWS.txt
  cp -f -p AUTHORS              "${_DST}"/AUTHORS.txt
  cp -f -p COPYING              "${_DST}"/COPYING.txt

  ../_pkg.sh "$(pwd)/${_ref}"
)
