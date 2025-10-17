#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cat /etc/*-release

export DEBIAN_FRONTEND='noninteractive'

[ "${1:-}" = '--sudo' ] && sudo='sudo' || sudo=''
extra=''
dl=''

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  [ -n "${CW_CCSUFFIX:-}" ] || export CW_CCSUFFIX='-19'
  extra+=" llvm${CW_CCSUFFIX} clang${CW_CCSUFFIX} lld${CW_CCSUFFIX} libclang-rt${CW_CCSUFFIX}-dev"
fi

[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' golang'

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra+=' gcc-mingw-w64-x86-64-win32 wine64 wine'
  [[ "${CW_CONFIG:-}" = *'x86'* ]] && extra+=' gcc-mingw-w64-i686-win32 wine32'
  # https://tracker.debian.org/pkg/osslsigncode
  extra+=' osslsigncode'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
    extra+=' g++-mingw-w64-x86-64-win32 nasm'
    [[ "${CW_CONFIG:-}" = *'x86'* ]] && extra+=' g++-mingw-w64-i686-win32'
  fi
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  [ -n "${CW_GCCSUFFIX:-}" ] || CW_GCCSUFFIX='-14'
  extra+=' checksec qemu-user-static'
  if [[ "${CW_CONFIG:-}" != *'gcc'* ]] || [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    if [ "$(uname -m)" = 'aarch64' ]; then
      ${sudo} dpkg --add-architecture amd64
    else
      ${sudo} dpkg --add-architecture arm64
    fi
    ${sudo} dpkg --add-architecture riscv64
  fi
  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    export CW_CCSUFFIX="${CW_GCCSUFFIX}"
    extra+=" gcc${CW_GCCSUFFIX}"
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra+=" gcc${CW_GCCSUFFIX}-x86-64-linux-gnu"
    else
      extra+=" gcc${CW_GCCSUFFIX}-aarch64-linux-gnu"
    fi
    extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu"
    if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
      extra+=" g++${CW_GCCSUFFIX}"
      if [ "$(uname -m)" = 'aarch64' ]; then
        extra+=" g++${CW_GCCSUFFIX}-x86-64-linux-gnu"
      else
        extra+=" g++${CW_GCCSUFFIX}-aarch64-linux-gnu"
      fi
      extra+=" g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
    fi
  else
    # ./my-pkg/usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.builtins-aarch64.a
    if [ "$(uname -m)" = 'aarch64' ]; then
      dl+=" libclang-rt${CW_CCSUFFIX}-dev:amd64"
    else
      dl+=" libclang-rt${CW_CCSUFFIX}-dev:arm64"
    fi
    dl+=" libclang-rt${CW_CCSUFFIX}-dev:riscv64"
  fi
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra+=' musl musl-dev'
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra+=' musl:amd64 musl-dev:amd64'
    else
      extra+=' musl:arm64 musl-dev:arm64'
    fi
    extra+=' musl:riscv64 musl-dev:riscv64'
    [[ "${CW_CONFIG:-}" = *'gcc'* ]] && extra+=" libgcc${CW_GCCSUFFIX}-dev"
    if [[ "${CW_CONFIG:-}" = *'openssl'* ]]; then
      # for openssl 'secure-memory' feature
      if [ "$(uname -m)" = 'aarch64' ]; then
        extra+=' linux-headers-arm64'
      elif [ "$(uname -m)" = 'x86_64' ]; then
        extra+=' linux-headers-amd64'
      fi
      extra+=' linux-headers-riscv64'
    fi
  else
    # FIXME: workaround for glibc-llvm-riscv64 builds:
    if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
      extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu"
      if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
        extra+=" g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
      fi
    fi
    if [ "$(uname -m)" = 'aarch64' ]; then
      extra+=' libc6-dev-amd64-cross'
    else
      extra+=' libc6-dev-arm64-cross'
    fi
    extra+=' libc6-dev-riscv64-cross'
  fi
fi

${sudo} apt-get --option Dpkg::Use-Pty=0 --yes update
# shellcheck disable=SC2086
${sudo} apt-get --option Dpkg::Use-Pty=0 --yes install --no-install-suggests --no-install-recommends \
  curl ca-certificates git gpg gpg-agent patch ssh rsync python3-pip python3-venv make cmake ninja-build \
  libssl-dev zlib1g-dev \
  zip xz-utils time jq secure-delete cosign ${extra}

if [ -n "${dl}" ]; then
  # shellcheck disable=SC2086
  apt-get --option Dpkg::Use-Pty=0 --yes download ${dl}
  # https://deb.debian.org/debian/pool/main/l/llvm-toolchain-17/libclang-rt-17-dev_17.0.5-1_arm64.deb -> libclang-rt-17-dev_1%3a17.0.5-1_arm64.deb
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
