#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

export CW_CCSUFFIX='-16'

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} golang nasm"
[[ "${CW_CONFIG:-}" = *'win'* ]] && extra="${extra} mingw-w64 osslsigncode wine64"

if [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra="${extra} musl musl-dev musl-tools"
    # for openssl 'secure-memory' feature
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra="${extra} linux-headers-arm64"
    elif [ "$(uname -m)" = 'x86_64' ]; then
      extra="${extra} linux-headers-amd64"
    fi
  fi
fi

apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
# shellcheck disable=SC2086
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  curl git gpg rsync python3-pefile make cmake \
  "llvm${CW_CCSUFFIX}" "clang${CW_CCSUFFIX}" "lld${CW_CCSUFFIX}" \
  autoconf automake autopoint libtool \
  zip time jq dos2unix secure-delete ${extra}

./_build.sh
