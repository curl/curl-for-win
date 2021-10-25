#!/bin/sh

# Copyright 2016-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  options=''

  # curl only required to talk to the timestamp server which we don't
  # use at the moment to remain deterministic.
  # options="${options} -DENABLE_CURL -lcurl"

  if [ "${_OS}" = 'mac' ]; then
    # options="-I/usr/local/opt/curl/include -L/usr/local/opt/curl/lib"
    options="${options} -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib"
  fi

  # shellcheck disable=SC2086
  gcc -O3 \
    osslsigncode.c msi.c -o ../osslsigncode-local \
    -DHAVE_SYS_MMAN_H \
    ${options} \
    "-DPACKAGE_VERSION=\"${_VER}\"" \
    "-DPACKAGE_STRING=\"osslsigncode ${_VER}\"" \
    '-DPACKAGE_BUGREPORT="none"' \
    -lcrypto
)
