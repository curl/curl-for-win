#!/usr/bin/env bash

# Copyright 2017-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  curl git gpg rsync python3-pip make cmake \
  libssl-dev \
  mingw-w64 llvm clang lld \
  autoconf automake autopoint libtool osslsigncode \
  zip time jq dos2unix secure-delete wine64

[[ "${APPVEYOR_REPO_BRANCH:-}" = *'boringssl'* ]] && \
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  golang nasm

./_build.sh
