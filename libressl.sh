#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Caveats (as of 3.9.1):
# - CET not enabled in mingw-w64 x64 ASM functions.
#   https://github.com/libressl/portable/pull/1032
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

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  options=''
  CFLAGS="-ffile-prefix-map=$(pwd)="
  CPPFLAGS=''

  if [[ "${_CONFIG}" != *'debug'* ]]; then
    CPPFLAGS+=' -DNDEBUG'
  fi

  if [ "${_CC}" = 'llvm' ]; then
    CFLAGS+=' -Wa,--noexecstack'
  else
    CFLAGS+=' -Wno-attributes'
  fi

  CPPFLAGS+=' -DS2N_BN_HIDE_SYMBOLS'

  if [ "${_OS}" = 'mac' ]; then
    CPPFLAGS+=' -Dglobl=private_extern'  # make assembly symbols hidden

    # Workaround for mis-detecting 'strtonum' successfully despite targeting
    # older OS version, then using it.
    if [ "${_OSVER}" -lt '1100' ]; then
      options+=' -DHAVE_STRTONUM=0'
    fi
  elif [ "${_OS}" = 'linux' ] && [ "${_CPU}" = 'x64' ]; then
    # Add a `.hidden <func>` next to each `.globl <func>` one:
    find . -name '*-elf-x86_64.S' | sort | while read -r f; do
      awk '/^\.globl\t/ {s=$0; sub("^.globl", ".hidden", s); print s}; {print}' < "${f}" > "${f}.tmp"
      mv "${f}.tmp" "${f}"
    done
  fi

  if [ "${CW_DEV_CMAKE_PREFILL:-}" = '1' ] && [ "${_OS}" = 'win' ]; then
    # fast-track configuration
    options+=' -DHAVE_ASPRINTF=1 -DHAVE_GETOPT=1 -DHAVE_REALLOCARRAY=0'
    options+=' -DHAVE_STRCASECMP=1 -DHAVE_STRLCAT=0 -DHAVE_STRLCPY=0 -DHAVE_STRNDUP=0 -DHAVE_STRSEP=0'
    options+=' -DHAVE_ARC4RANDOM_BUF=0 -DHAVE_ARC4RANDOM_UNIFORM=0 -DHAVE_EXPLICIT_BZERO=0'
    options+=' -DHAVE_GETAUXVAL=0 -DHAVE_GETENTROPY=0 -DHAVE_GETPAGESIZE=0 -DHAVE_GETPROGNAME=0'
    options+=' -DHAVE_SYSLOG_R=0 -DHAVE_SYSLOG=0'
    options+=' -DHAVE_TIMEGM=0 -DHAVE_TIMESPECSUB=0 -DHAVE_TIMINGSAFE_BCMP=0 -DHAVE_TIMINGSAFE_MEMCMP=0'
    options+=' -DHAVE_MEMMEM=0 -DHAVE_ENDIAN_H=0 -DHAVE_MACHINE_ENDIAN_H=0 -DHAVE_ERR_H=0 -DHAVE_NETINET_IP_H=0 -DHAVE_CLOCK_GETTIME=0'
    options+=' -DHAVE_SYS_TYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STDDEF_H=1'
  fi

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    "-DCMAKE_SYSTEM_PROCESSOR=${_TRIPLET}" \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DLIBRESSL_APPS=OFF' \
    '-DLIBRESSL_TESTS=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${CPPFLAGS} ${_LDFLAGS_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

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
)
