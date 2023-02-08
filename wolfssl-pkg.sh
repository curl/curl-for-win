#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

{
  # Make steps for determinism

  readonly _ref='ChangeLog.md'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(realpath _pkg)"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/wolfssl/openssl"
  mkdir -p "${_DST}/include/wolfssl/wolfcrypt"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/wolfssl/openssl/*.h   "${_DST}/include/wolfssl/openssl"
  cp -f -p "${_PP}"/include/wolfssl/wolfcrypt/*.h "${_DST}/include/wolfssl/wolfcrypt"
  cp -f -p "${_PP}"/include/wolfssl/*.h           "${_DST}/include/wolfssl"
  cp -f -p "${_PP}"/lib/*.a                       "${_DST}/lib/"
  cp -f -p ChangeLog.md                           "${_DST}/"
  cp -f -p README.md                              "${_DST}/"
  cp -f -p COPYING                                "${_DST}/COPYING.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
}
