#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Caveats (as of 3.9.0):
# - crash on startup after 3.8.3, with mingw-w64 x64 with ASM and CET enabled.
#   https://github.com/libressl/portable/issues/1015
# - CMake builds override -NDEBUG and do not allow building with this option. [FIX MERGED THEN LOST] https://github.com/libressl/portable/pull/988
# - ASM support only for x64.
# - Not possible to hide most ASM symbols from shared lib exports in Linux, macOS.
#   https://github.com/libressl/portable/issues/957
#   Local patch exists for this, or ASM can be disabled.
# - Non-namespaced functions are defined and exported from libcrypto. [FIXED IN 3.9.0?]
#   This causes a list of issues, from mis-detection, mis-use, unhidden
#   export from shared lib. Mostly affects macOS.
#   https://github.com/libressl/portable/issues/928
# - Still loads config from hardcoded prefix.
# - Missing `SSL_set0_wbio()` function.
#   https://github.com/libressl/portable/issues/838
# - No obvious way to selectively disable obsolete protocols/APIs/features.
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

  # shellcheck disable=SC2066
  for bin in \
    "${_PP}/bin/openssl${BIN_EXT}"
  do
    if [ -f "${bin}" ]; then
      file "${bin}"
      # Produce 'openssl version -a'-like output without executing the build:
      strings "${bin}" | grep -a -E '^(LibreSSL [0-9]|built on: |compiler: |platform: |[A-Z]+DIR: )' || true
    fi
  done

  # List files created
  find "${_PP}" | grep -a -v -F '/share/' | sort

  # Build fixups

  # We want to keep this package as interchangeable with other openssl forks
  # as possible. Do not distribute the libressl-specific libtls at this time.
  # libtls also has pending issue when built with CMake, as of v3.8.2.
  rm -f "${_PP}/lib/libtls.a"
  rm -f "${_PP}/include/tls.h"

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
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README.md                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
}
