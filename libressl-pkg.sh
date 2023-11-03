#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Caveats (as of 3.8.1):
# - ASM support exist only for x64 on Windows.
# - Still loads config/DLLs from the hardcoded prefix. (improvements coming in 3.8.1)
# - Unexpected warnings when building with ASM _enabled_ and CMake:
#   ```
#   In file included from ./libressl/crypto/bn/bn_mul.c:65:
#   ./libressl/crypto/bn/arch/amd64/bn_arch.h:24:9: warning: 'OPENSSL_NO_ASM' macro redefined [-Wmacro-redefined]
#   #define OPENSSL_NO_ASM
#           ^
#   <command line>:10:9: note: previous definition is here
#   #define OPENSSL_NO_ASM 1
#           ^
#   ```
#   Ref: https://github.com/libressl/portable/issues/910#issuecomment-1754180366
# - `-Wattributes` warnings with gcc. Need to be silenced with `-Wno-attributes`:
#   ```
#   ../../crypto/chacha/chacha-merged.c:26:5: warning: 'bounded' attribute directive ignored [-Wattributes]
#      26 |     __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
#         |     ^~~~~~~~~~~~~
#   ../../crypto/chacha/chacha-merged.c:30:5: warning: 'bounded' attribute directive ignored [-Wattributes]
#      30 |     __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
#         |     ^~~~~~~~~~~~~
#   ../../crypto/chacha/chacha-merged.c:30:5: warning: 'bounded' attribute directive ignored [-Wattributes]
#   ../../crypto/chacha/chacha-merged.c:34:5: warning: 'bounded' attribute directive ignored [-Wattributes]
#      34 |     __attribute__((__bounded__(__buffer__, 3, 4)));
#         |     ^~~~~~~~~~~~~
#   ```
#   Ref: https://github.com/libressl/portable/issues/910#issuecomment-1755219504

{
  # Tests

  # shellcheck disable=SC2043
  for bin in \
    "${_PP}/bin/openssl${BIN_EXT}" \
  ; do
    if [ -f "${bin}" ]; then
      file "${bin}"
      # Produce 'openssl version -a'-like output without executing the build:
      strings "${bin}" | grep -a -E '^(LibreSSL [0-9]|built on: |compiler: |platform: |[A-Z]+DIR: )' || true
    fi
  done

  # List files created
  find "${_PP}" | grep -a -v -F '/share/' | sort

  # Make steps for determinism

  readonly _ref='ChangeLog'

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_PP}"/include/*.h         "${_DST}/include/"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README.md                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
}
