#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

LLVM='17'

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' go'

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra+=' mingw-w64-gcc-base wine'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    extra+=' nasm'
  fi
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  apk add --no-cache checksec-rs --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community/
  extra+=' compiler-rt libc++-static'  # for llvm
  if [[ "${CW_CONFIG:-}" =~ (quictls|openssl) ]]; then
    extra+=' linux-headers'  # for openssl 'secure-memory' feature
  fi
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra+=' gcc'
  fi
fi

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  extra+=" llvm${LLVM} clang${LLVM} lld"
fi

# https://pkgs.alpinelinux.org/packages
# shellcheck disable=SC2086
apk add --no-cache curl git gpg gpg-agent rsync build-base cmake python3 \
  zip tar xz jq openssl ${extra}

./_build.sh
