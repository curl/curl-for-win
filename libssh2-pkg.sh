#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

{
  # Make steps for determinism

  readonly _ref='NEWS'

  rm -f "${_PP}"/lib/*.dll.a

  # shellcheck disable=SC2086
  "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p "${_PP}"/include/*.h "${_DST}/include/"
  cp -f -p "${_PP}"/lib/*.a     "${_DST}/lib/"
  cp -f -p NEWS                 "${_DST}/NEWS.txt"
  cp -f -p COPYING              "${_DST}/COPYING.txt"
  cp -f -p README               "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES        "${_DST}/RELEASE-NOTES.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
}
