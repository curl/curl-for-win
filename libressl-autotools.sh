#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-autotools//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  [ -f 'configure' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} ${_CFLAGS_GLOBAL_AUTOTOOLS}"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL_AUTOTOOLS}"
  export LIBS=''

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

    if [ "${_OSVER}" -lt '1100' ]; then
      # Workaround for mis-detecting 'strtonum' successfully despite targeting
      # older OS version, then using it, and showing these warnings while
      # possibly breaking when run on older macOS versions:
      #   ../../crypto/x509/x509_addr.c:1629:17: warning: 'strtonum' is only available on macOS 11.0 or newer [-Wunguarded-availability-new]
      #   ../../../apps/ocspcheck/ocspcheck.c:169:8: warning: 'strtonum' is only available on macOS 11.0 or newer [-Wunguarded-availability-new]
      #   [...]
      # Ref: https://github.com/libressl/portable/issues/910
      # This setting force-disables this function and makes LibreSSL use its
      # own internal implementation instead. Notice this makes warnings even
      # more verbose.
      export ac_cv_func_strtonum='no'
    fi
  elif [ "${_OS}" = 'linux' ] && [ "${_CPU}" = 'x64' ]; then
    # Add a `.hidden <func>` next to each `.globl <func>` one:
    find . -name '*-elf-x86_64.S' | sort | while read -r f; do
      awk '/^\.globl\t/ {s=$0; sub("^.globl", ".hidden", s); print s}; {print}' < "${f}" > "${f}.tmp"
      mv "${f}.tmp" "${f}"
    done
  fi

  if [ "${_OS}" = 'win' ]; then
    _my_prefix='C:/Windows/libressl'
  else
    _my_prefix='/etc'
  fi
  _ssldir='ssl'

  (
    mkdir "${_BLDDIR}"; cd "${_BLDDIR}"
    # shellcheck disable=SC2086
    ../configure ${options} \
      --enable-static \
      --disable-shared \
      --disable-tests \
      "--prefix=${_my_prefix}" \
      "--with-openssldir=${_my_prefix}/${_ssldir}" --silent
  )

  # Ending slash required.
  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}/" >/dev/null # 2>&1

  # LibreSSL does not strip the drive letter
  #   ./libressl/${_PKGDIR}/C:/Windows/libressl
  # Some tools (e.g. CMake) become weird when colons appear in a filename,
  # so move results to a sane, standard path:

  mkdir -p "./${_PP}"
  mv "${_PKGDIR}/${_my_prefix}"/* "${_PP}"

  # Delete .pc and .la files
  rm -r -f "${_PP}"/lib/pkgconfig
  rm -f    "${_PP}"/lib/*.la

  . ../libressl-pkg.sh
)
