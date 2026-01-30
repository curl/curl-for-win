#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

LLVM=''

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' go'

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra+=' mingw-w64-gcc-base'
  [[ "${CW_CONFIG:-}" != *'noWINE'* ]] && extra+=' wine'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
    extra+=' nasm'
  fi
  [ -n "${DEPLOY_AGE_PASS:+1}" ] && extra+=' openssh-client-default'
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  apk add --no-cache checksec-rs --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community/
  extra+=' compiler-rt'  # for llvm
  extra+=' linux-headers'  # for curl 'linux/tcp.h' and openssl 'secure-memory' feature
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
    extra+=' libc++-static'  # for llvm
  fi
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra+=' gcc'
  fi
fi

[[ ! "${CW_CONFIG}" =~ (zero|bldtst|nocookie) ]] && extra+=' python3'  # for libpsl

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  extra+=" llvm${LLVM} clang${LLVM} lld"
fi

[ -n "${COSIGN_AGE_PASS:+1}" ] && extra+=' cosign'
[ -n "${MINISIGN_AGE_PASS:+1}" ] && extra+=' minisign'

[ -n "${SIGN_CODE_AGE_PASS:+1}${COSIGN_AGE_PASS:+1}${DEPLOY_AGE_PASS:+1}${MINISIGN_AGE_PASS:+1}${SIGN_PKG_AGE_PASS:+1}" ] && extra+=' age'

# https://pkgs.alpinelinux.org/packages
# shellcheck disable=SC2086
apk add --no-cache curl git gpg gpg-agent rsync build-base cmake samurai \
  zip tar xz jq openssl sed perl ${extra}

./_build.sh
