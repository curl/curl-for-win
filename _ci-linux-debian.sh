#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

extra=''
dl=''

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
  if [[ "${CW_CONFIG:-}" != *'gcc'* ]] || [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    if [ "$(uname -m)" = 'aarch64' ]; then
      dpkg --add-architecture amd64
    else
      dpkg --add-architecture arm64
    fi
  fi
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra="${extra} gcc${CW_GCCSUFFIX} g++${CW_GCCSUFFIX}"
    export CW_CCSUFFIX="${CW_GCCSUFFIX}"
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra="${extra} gcc${CW_GCCSUFFIX}-x86-64-linux-gnu g++${CW_GCCSUFFIX}-x86-64-linux-gnu"
    else
      extra="${extra} gcc${CW_GCCSUFFIX}-aarch64-linux-gnu g++${CW_GCCSUFFIX}-aarch64-linux-gnu"
    fi
  else
    # These packages do not install due to dependency requirements.
    # We download unpack them manually as a workaround.
    if [ "${CW_CCSUFFIX}" = '-15' ]; then
      # ./my-pkg/usr/lib/clang/15/lib
      # ./my-pkg/usr/lib/llvm-15/lib/clang/15.0.6/lib/linux/libclang_rt.builtins-aarch64.a
      if [ "$(uname -m)" = 'aarch64' ]; then
        dl="${dl} libclang-common${CW_CCSUFFIX}-dev:amd64"
      else
        dl="${dl} libclang-common${CW_CCSUFFIX}-dev:arm64"
      fi
    else
      # ./my-pkg/usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.builtins-aarch64.a
      if [ "$(uname -m)" = 'aarch64' ]; then
        dl="${dl} libclang-rt${CW_CCSUFFIX}-dev:amd64"
      else
        dl="${dl} libclang-rt${CW_CCSUFFIX}-dev:arm64"
      fi
    fi
  fi
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra="${extra} musl musl-dev"
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra="${extra} musl:amd64 musl-dev:amd64"
    else
      extra="${extra} musl:arm64 musl-dev:arm64"
    fi
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
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra="${extra} libc6-dev-amd64-cross"
    else
      extra="${extra} libc6-dev-arm64-cross"
    fi
  fi
fi

apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
# shellcheck disable=SC2086
apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
  curl git gpg rsync python3-pefile make cmake \
  autoconf automake autopoint libtool \
  zip time jq secure-delete ${extra}

if [ -n "${dl}" ]; then
  # shellcheck disable=SC2086
  apt-get --quiet 2 --option Dpkg::Use-Pty=0 download ${dl}
  # https://deb.debian.org/debian/pool/main/l/llvm-toolchain-16/libclang-rt-16-dev_16.0.6-16_arm64.deb -> libclang-rt-16-dev_1%3a16.0.6-16_arm64.deb
  # libclang-common-15-dev_1%3a15.0.6-4+b1_amd64.deb
  dpkg-deb --contents ./*.deb
  dpkg-deb --extract --verbose ./*.deb my-pkg
  if [ ! -d 'my-pkg/usr/lib/clang' ]; then
    ln -s -f "llvm${CW_CCSUFFIX}/lib/clang" 'my-pkg/usr/lib/clang'
  fi
  find -L 'my-pkg/usr/lib/clang' | sort
fi

./_build.sh
