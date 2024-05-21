#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

export DEBIAN_FRONTEND='noninteractive'

extra=''
dl=''

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  [ -n "${CW_CCSUFFIX:-}" ] || export CW_CCSUFFIX='-17'
  extra+=" llvm${CW_CCSUFFIX} clang${CW_CCSUFFIX} lld${CW_CCSUFFIX}"
fi

[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' golang'

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra+=' mingw-w64 wine64'
# extra+=' osslsigncode'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    extra+=' nasm'
  fi
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  [ -n "${CW_GCCSUFFIX:-}" ] || CW_GCCSUFFIX='-14'
  extra+=' checksec qemu-user-static'
  if [[ "${CW_CONFIG:-}" != *'gcc'* ]] || [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    if [ "$(uname -m)" = 'aarch64' ]; then
      dpkg --add-architecture amd64
    else
      dpkg --add-architecture arm64
    fi
    [[ "${CW_CONFIG:-}" = *'r64'* ]] && dpkg --add-architecture riscv64
  fi
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra+=" gcc${CW_GCCSUFFIX} g++${CW_GCCSUFFIX}"
    export CW_CCSUFFIX="${CW_GCCSUFFIX}"
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra+=" gcc${CW_GCCSUFFIX}-x86-64-linux-gnu g++${CW_GCCSUFFIX}-x86-64-linux-gnu"
    else
      extra+=" gcc${CW_GCCSUFFIX}-aarch64-linux-gnu g++${CW_GCCSUFFIX}-aarch64-linux-gnu"
    fi
    [[ "${CW_CONFIG:-}" = *'r64'* ]] && extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
  else
    # These packages do not install due to dependency requirements.
    # We download unpack them manually as a workaround.
    if [ "${CW_CCSUFFIX}" = '-15' ]; then
      # ./my-pkg/usr/lib/clang/15/lib
      # ./my-pkg/usr/lib/llvm-15/lib/clang/15.0.6/lib/linux/libclang_rt.builtins-aarch64.a
      if [ "$(uname -m)" = 'aarch64' ]; then
        dl+=" libclang-common${CW_CCSUFFIX}-dev:amd64"
      else
        dl+=" libclang-common${CW_CCSUFFIX}-dev:arm64"
      fi
      [[ "${CW_CONFIG:-}" = *'r64'* ]] && dl+=" libclang-common${CW_CCSUFFIX}-dev:riscv64"
    else
      # ./my-pkg/usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.builtins-aarch64.a
      if [ "$(uname -m)" = 'aarch64' ]; then
        dl+=" libclang-rt${CW_CCSUFFIX}-dev:amd64"
      else
        dl+=" libclang-rt${CW_CCSUFFIX}-dev:arm64"
      fi
      [[ "${CW_CONFIG:-}" = *'r64'* ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:riscv64"
    fi
  fi
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra+=' musl musl-dev'
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra+=' musl:amd64 musl-dev:amd64'
    else
      extra+=' musl:arm64 musl-dev:arm64'
    fi
    [[ "${CW_CONFIG:-}" = *'r64'* ]] && extra+=' musl:riscv64 musl-dev:riscv64'
    if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
      extra+=" libgcc${CW_GCCSUFFIX}-dev"
    fi
    if [[ "${CW_CONFIG:-}" =~ (quictls|openssl) ]]; then
      # for openssl 'secure-memory' feature
      if [ "$(uname -m)" = 'aarch64' ]; then
        extra+=' linux-headers-arm64'
      elif [ "$(uname -m)" = 'x86_64' ]; then
        extra+=' linux-headers-amd64'
      fi
    fi
  else
    # FIXME: workaround for glibc-llvm-riscv64 builds:
    [[ "${CW_CONFIG:-}" != *'gcc'* ]] && [[ "${CW_CONFIG:-}" = *'r64'* ]] && extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra+=' libc6-dev-amd64-cross'
    else
      extra+=' libc6-dev-arm64-cross'
    fi
    [[ "${CW_CONFIG:-}" = *'r64'* ]] && extra+=' libc6-dev-riscv64-cross'
  fi
fi

apt-get --option Dpkg::Use-Pty=0 --yes update
# shellcheck disable=SC2086
apt-get --option Dpkg::Use-Pty=0 --yes install \
  curl git gpg gpg-agent rsync python3-pefile make cmake \
  libssl-dev zlib1g-dev \
  zip xz-utils time jq secure-delete ${extra}

if [ -n "${dl}" ]; then
  # shellcheck disable=SC2086
  apt-get --option Dpkg::Use-Pty=0 --yes download ${dl}
  # https://deb.debian.org/debian/pool/main/l/llvm-toolchain-17/libclang-rt-17-dev_17.0.5-1_arm64.deb -> libclang-rt-17-dev_1%3a17.0.5-1_arm64.deb
  # libclang-common-15-dev_1%3a15.0.6-4+b1_amd64.deb
  for f in ./*.deb; do
    dpkg-deb --contents "${f}"
    dpkg-deb --extract --verbose "${f}" my-pkg
  done
  if [ ! -d 'my-pkg/usr/lib/clang' ]; then
    ln -s -f "llvm${CW_CCSUFFIX}/lib/clang" 'my-pkg/usr/lib/clang'
  fi
  find -L 'my-pkg/usr/lib/clang' | sort
fi

./_build.sh
