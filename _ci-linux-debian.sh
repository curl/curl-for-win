#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

export _CCSUFFIX=''
[ "${CC}" = 'mingw-clang' ] && _optpkg="clang${_CCSUFFIX}"

dpkg --add-architecture i386
apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  curl git gpg rsync python3-pip make cmake \
  libssl-dev \
  gcc-mingw-w64 g++-mingw-w64 ${_optpkg} \
  autoconf automake autopoint libtool \
  zip zstd time jq dos2unix secure-delete wine64 wine32

./_build.sh
