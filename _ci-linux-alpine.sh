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
  if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    extra+=' nasm'
  fi
  extra+=' py3-pefile'
  [ -n "${DEPLOY_AGE_PASS:+1}" ] && extra+=' openssh-client-default'
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  apk add --no-cache checksec-rs --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community/
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra+=' gcc musl-dev'
    if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
      extra+=' g++'
    fi
  else
    extra+=' compiler-rt'  # for llvm
    if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
      extra+=' libstdc++-dev'
    fi
  fi
  if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'openssl'* ]]; then
    extra+=' linux-headers'  # for awslc/boringssl 'linux/random.h', openssl 'secure-memory' feature requiring 'linux/mman.h'
  fi
fi
extra+=' make'  # for trurl <=1.16.1

[[ ! "${CW_CONFIG}" =~ (zero|bldtst|nocookie) ]] && extra+=' python3'  # for libpsl

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  extra+=" llvm${LLVM} clang${LLVM} lld"
fi

[ -n "${COSIGN_AGE_PASS:+1}" ] && extra+=' cosign'
[ -n "${MINISIGN_AGE_PASS:+1}" ] && extra+=' minisign'
[ -n "${SIGN_SSH_AGE_PASS:+1}" ] && extra+=' openssh-client-default'

[ -n "${SIGN_CODE_AGE_PASS:+1}${COSIGN_AGE_PASS:+1}${DEPLOY_AGE_PASS:+1}${MINISIGN_AGE_PASS:+1}${SIGN_PKG_AGE_PASS:+1}${SIGN_SSH_AGE_PASS:+1}" ] && extra+=' age'

# https://pkgs.alpinelinux.org/packages
# coreutils to override the busybox sha256sum implementation for `--tag` option support.
# shellcheck disable=SC2086
apk add --no-cache curl git gpg gpg-agent rsync cmake samurai patch file g++ \
  zip tar xz jq coreutils sed perl ${extra}

./_build.sh
