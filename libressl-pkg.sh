#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Caveats (as of 3.8.2):
# - ASM support only for x64.
# - ASM missing Intel CET support, resulting in linker warnings:
#   ld.lld-17: warning: libressl/_x64-linux-gnu/usr/lib/libcrypto.a(cpuid-elf-x86_64.S.o): -z cet-report: file does not have GNU_PROPERTY_X86_FEATURE_1_IBT property
#   ld.lld-17: warning: libressl/_x64-linux-gnu/usr/lib/libcrypto.a(cpuid-elf-x86_64.S.o): -z cet-report: file does not have GNU_PROPERTY_X86_FEATURE_1_SHSTK property
#   https://github.com/curl/curl-for-win/actions/runs/7159857921/job/19493575609#step:3:11146
# - No possible to hide most ASM symbols from shared lib exports in Linux, macOS.
#   https://github.com/libressl/portable/issues/957
#   Local patch exists for this, or ASM can be disabled.
# - Non-namespaced functions are defined and exported from libcrypto. [fix pending]
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
