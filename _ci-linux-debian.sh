#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

extra=''

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  [ -n "${CW_CCSUFFIX:-}" ] || export CW_CCSUFFIX='-16'
  extra="${extra} llvm${CW_CCSUFFIX} clang${CW_CCSUFFIX} lld${CW_CCSUFFIX}"
fi

[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} golang"

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra="${extra} mingw-w64 osslsigncode wine64"
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
    extra="${extra} nasm"
  fi
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  [ -n "${CW_GCCSUFFIX:-}" ] || CW_GCCSUFFIX='-13'
  extra="${extra} checksec"
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra="${extra} gcc${CW_GCCSUFFIX} g++${CW_GCCSUFFIX}"
    export CW_CCSUFFIX="${CW_GCCSUFFIX}"
  fi
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra="${extra} musl musl-dev"
    if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
      extra="${extra} libgcc${CW_GCCSUFFIX}-dev"
    fi
    # for openssl 'secure-memory' feature
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra="${extra} linux-headers-arm64"
    elif [ "$(uname -m)" = 'x86_64' ]; then
      extra="${extra} linux-headers-amd64"
    fi
  else
    if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
      if [ "$(uname -m)" = 'aarch64' ]; then
        extra="${extra} gcc${CW_GCCSUFFIX}-x86-64-linux-gnu g++${CW_GCCSUFFIX}-x86-64-linux-gnu"
      else
        extra="${extra} gcc${CW_GCCSUFFIX}-aarch64-linux-gnu g++${CW_GCCSUFFIX}-aarch64-linux-gnu"
      fi
    else
      if [ "$(uname -m)" = 'aarch64' ]; then
        extra="${extra} libgcc${CW_GCCSUFFIX}-dev-amd64-cross libstdc++${CW_GCCSUFFIX}-dev-amd64-cross"
      else
        extra="${extra} libgcc${CW_GCCSUFFIX}-dev-arm64-cross libstdc++${CW_GCCSUFFIX}-dev-arm64-cross"
      fi
    fi
  fi
fi

apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
# shellcheck disable=SC2086
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  curl git gpg rsync python3-pefile make cmake \
  autoconf automake autopoint libtool \
  zip time jq secure-delete ${extra}

./_build.sh
