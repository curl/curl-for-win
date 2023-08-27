#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

export CW_CCSUFFIX='-16'

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} golang nasm"

apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
# shellcheck disable=SC2086
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  curl git gpg rsync python3-pefile make cmake \
  mingw-w64 \
  "llvm${CW_CCSUFFIX}" "clang${CW_CCSUFFIX}" "lld${CW_CCSUFFIX}" \
  autoconf automake autopoint libtool osslsigncode \
  zip time jq dos2unix secure-delete wine64 ${extra}

./_build.sh
