#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

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

  # FIXME upstream: debug options are permanently force-enabled. [FIX MERGED THEN LOST]
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

  . ../libressl-pkg.sh
)
