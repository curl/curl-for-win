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
  [ -n "${CW_CCSUFFIX:-}" ] || export CW_CCSUFFIX='-21'
  if [[ "${CW_CONFIG:-}" != *'win'* ]] || [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ]; then
    extra+=" llvm${CW_CCSUFFIX} clang${CW_CCSUFFIX} lld${CW_CCSUFFIX} libclang-rt${CW_CCSUFFIX}-dev"
  fi
fi

[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' golang'

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  if [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ]; then
    extra+=' gcc-mingw-w64-x86-64-win32'
  elif [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    extra+=' binutils-mingw-w64-x86-64'
  fi
  [[ "${CW_CONFIG:-}" != *'noWINE'* ]] && extra+=' wine64 wine'
  if [[ "${CW_CONFIG:-}" = *'x86'* ]]; then
    if [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ]; then
      extra+=' gcc-mingw-w64-i686-win32'
    elif [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
      extra+=' binutils-mingw-w64-i686'
    fi
    extra+=' wine32'
  fi
  # https://tracker.debian.org/pkg/osslsigncode
  extra+=' osslsigncode'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
    [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ] && extra+=' g++-mingw-w64-x86-64-win32'
    extra+=' nasm'
    if [[ "${CW_CONFIG:-}" = *'x86'* ]]; then
      [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ] && extra+=' g++-mingw-w64-i686-win32'
    fi
  fi
  extra+=' python3-pip python3-venv'  # for pefile and libpsl
  [ -n "${DEPLOY_AGE_PASS:+1}" ] && extra+=' openssh-client'
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  [ -n "${CW_GCCSUFFIX:-}" ] || CW_GCCSUFFIX='-14'

  [ "${CW_TRURL_TEST:-}" = '1' ] && extra+=' python3'

  extra+=' checksec'

  [[ ! "${CW_CONFIG}" =~ (zero|bldtst|nocookie) ]] && extra+=' python3'  # for libpsl

  x64=0; a64=0; r64=0
  [[ "${CW_CONFIG}" = *'a64'* || ! "${CW_CONFIG}" =~ (x64|r64) ]] && a64=1
  [[ "${CW_CONFIG}" = *'r64'* || ! "${CW_CONFIG}" =~ (a64|x64) ]] && r64=1
  [[ "${CW_CONFIG}" = *'x64'* || ! "${CW_CONFIG}" =~ (a64|r64) ]] && x64=1

  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    anycross=0
    [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && anycross=1
    [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && anycross=1
    [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && anycross=1
    [ "${anycross}" = 1 ] && extra+=' qemu-user-static'
  fi

  if [[ "${CW_CONFIG:-}" != *'gcc'* ]] || [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && ${sudo} dpkg --add-architecture arm64
    [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && ${sudo} dpkg --add-architecture riscv64
    [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && ${sudo} dpkg --add-architecture amd64
  fi

  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    export CW_CCSUFFIX="${CW_GCCSUFFIX}"
    extra+=" gcc${CW_GCCSUFFIX}"
    [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && extra+=" gcc${CW_GCCSUFFIX}-aarch64-linux-gnu"
    [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu"
    [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && extra+=" gcc${CW_GCCSUFFIX}-x86-64-linux-gnu"
    if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
      extra+=" g++${CW_GCCSUFFIX}"
      [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && extra+=" g++${CW_GCCSUFFIX}-aarch64-linux-gnu"
      [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && extra+=" g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
      [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && extra+=" g++${CW_GCCSUFFIX}-x86-64-linux-gnu"
    fi
  else
    # ./my-pkg/usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.builtins-aarch64.a
    [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:arm64"
    [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:riscv64"
    [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:amd64"
  fi
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra+=' musl musl-dev'
    [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && extra+=' musl:arm64 musl-dev:arm64'
    [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && extra+=' musl:riscv64 musl-dev:riscv64'
    [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && extra+=' musl:amd64 musl-dev:amd64'

    [[ "${CW_CONFIG:-}" = *'gcc'* ]] && extra+=" libgcc${CW_GCCSUFFIX}-dev"

    # for curl 'linux/tcp.h' and openssl 'secure-memory' feature
    [[ "$(uname -m)" = 'aarch64' && "${a64}" = 1 ]] && extra+=' linux-headers-arm64'
    [[ "$(uname -m)" = 'riscv64' && "${r64}" = 1 ]] && extra+=' linux-headers-riscv64'
    [[ "$(uname -m)" = 'x86_64'  && "${x64}" = 1 ]] && extra+=' linux-headers-amd64'
  else  # glibc
    # FIXME: workaround for glibc-llvm-riscv64 builds:
    if [[ "${CW_CONFIG:-}" != *'gcc'* && "${r64}" = 1 ]]; then
      extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu"
      if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
        extra+=" g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
      fi
    fi
    [[ "$(uname -m)" != 'aarch64' && "${a64}" = 1 ]] && extra+=' libc6-dev-arm64-cross'
    [[ "$(uname -m)" != 'riscv64' && "${r64}" = 1 ]] && extra+=' libc6-dev-riscv64-cross'
    [[ "$(uname -m)" != 'x86_64'  && "${x64}" = 1 ]] && extra+=' libc6-dev-amd64-cross'

    anynoncross=0
    [[ "$(uname -m)" = 'aarch64' && "${a64}" = 1 ]] && anynoncross=1
    [[ "$(uname -m)" = 'riscv64' && "${r64}" = 1 ]] && anynoncross=1
    [[ "$(uname -m)" = 'x86_64'  && "${x64}" = 1 ]] && anynoncross=1
    [ "${anynoncross}" = 1 ] && extra+=' libc6-dev'
  fi
fi

[ -n "${COSIGN_AGE_PASS:+1}" ] && extra+=' cosign'
[ -n "${MINISIGN_AGE_PASS:+1}" ] && extra+=' minisign'

[ -n "${SIGN_CODE_AGE_PASS:+1}${COSIGN_AGE_PASS:+1}${DEPLOY_AGE_PASS:+1}${MINISIGN_AGE_PASS:+1}${SIGN_PKG_AGE_PASS:+1}" ] && extra+=' age'

${sudo} apt-get --option Dpkg::Use-Pty=0 --yes update
# shellcheck disable=SC2086
${sudo} apt-get --option Dpkg::Use-Pty=0 --yes install --no-install-suggests --no-install-recommends \
  curl ca-certificates git gpg gpg-agent patch rsync make cmake ninja-build \
  zip xz-utils time jq secure-delete ${extra}

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
