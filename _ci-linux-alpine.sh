#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

LLVM='16'

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} go"

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra="${extra} mingw-w64-gcc-base wine"
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
    extra="${extra} nasm"
  fi
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  apk add --no-cache checksec-rs --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing/
  extra="${extra} compiler-rt libc++-static"  # for llvm
  extra="${extra} linux-headers"  # for openssl 'secure-memory' feature
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra="${extra} gcc"
  fi
fi

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  extra="${extra} llvm${LLVM} clang${LLVM} lld"
fi

# https://pkgs.alpinelinux.org/packages
# shellcheck disable=SC2086
apk add --no-cache curl git gpg rsync build-base cmake \
  autoconf automake libtool \
  zip tar xz jq openssl ${extra}

./_build.sh
