#!/bin/sh -x

# Copyright 2016-2019 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

export _NAM
export _VER

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  # Detect host OS
  case "$(uname)" in
    *_NT*)   os='win';;
    Linux*)  os='linux';;
    Darwin*) os='mac';;
    *BSD)    os='bsd';;
  esac

  options=''

  # curl only required to talk to the timestamp server which we don't
  # use at the moment to remain deterministic.
  # options="${options} -DENABLE_CURL -lcurl"

  if [ "${os}" = 'mac' ]; then
    # options="-I/usr/local/opt/curl/include -L/usr/local/opt/curl/lib"
    options="${options} -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib"
  fi

  # shellcheck disable=SC2086
  gcc -O3 \
    osslsigncode.c -o ../osslsigncode-determ \
    -DHAVE_SYS_MMAN_H \
    ${options} \
    '-DPACKAGE_BUGREPORT="none"' \
    "-DPACKAGE_STRING=\"osslsigncode ${_VER}-determfix\"" \
    -lcrypto
)
