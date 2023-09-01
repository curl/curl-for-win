#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Caveats (as of 3.8.1):
# - ASM support exist only for x64 on Windows.
# - Building broken executables with ASM support enabled (both autotools and CMake).
#   Regression since 3.7.3.
# - Still loads config/DLLs from the hardcoded prefix. (improvements coming in 3.8.1)
# - Collision with wincrypt.h header when using with curl.
#   Ref: https://ci.appveyor.com/project/curlorg/curl-for-win/builds/47723913?fullLog=true#L24711
#   ```
#   ../../libressl/x64-ucrt/usr/include/openssl/ossl_typ.h:90:2: warning: #warning is a C2x extension [-Wpedantic]
#   #warning overriding WinCrypt defines
#    ^
#   ../../libressl/x64-ucrt/usr/include/openssl/ossl_typ.h:90:2: warning: overriding WinCrypt defines [-W#warnings]
#   ```
# - Extensive warnings about colliding function declaration attributes.
#   Ref: https://ci.appveyor.com/project/curlorg/curl-for-win/builds/47723913?fullLog=true#L4802
#   ```
#   In file included from ../../crypto/malloc-wrapper.c:19:
#   ../../include/compat/string.h:31:5: warning: '_strnicmp' redeclared without 'dllimport' attribute: previous 'dllimport' ignored [-Winconsistent-dllimport]
#   int strncasecmp(const char *s1, const char *s2, size_t len);
#       ^
#   /usr/x86_64-w64-mingw32/include/string.h:119:21: note: expanded from macro 'strncasecmp'
#   ```
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

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(realpath .)/_pkg"; rm -r -f "${_DST}"

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
