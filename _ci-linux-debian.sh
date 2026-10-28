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

# Requires obtaining a CA root bundle via cleartext. Or from the host
# machine. Both fragile/complex/slow/insecure.
# https://github.com/debuerreotype/docker-debian-artifacts/issues/28
# https://github.com/debuerreotype/docker-debian-artifacts/issues/15
if false; then
  # Install CA roots. It has the side-effect of also installing the openssl
  # tool as a hard dependency, as of Forky.
  ${sudo} apt-get --option Dpkg::Use-Pty=0 --yes update
  ${sudo} apt-get --option Dpkg::Use-Pty=0 --yes install --no-install-suggests --no-install-recommends ca-certificates
  # Update sources to use HTTPS
  ${sudo} sed -i 's/http:/https:/g' /etc/apt/sources.list.d/debian.sources
fi

[ -n "${CW_CCSUFFIX:-}" ] || export CW_CCSUFFIX='-22'

if [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  if [[ "${CW_CONFIG:-}" != *'win'* ]] || [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ]; then
    extra+=" llvm${CW_CCSUFFIX} clang${CW_CCSUFFIX} lld${CW_CCSUFFIX} libclang-rt${CW_CCSUFFIX}-dev"
  fi
fi

[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' golang'

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  if [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ]; then
    extra+=' gcc-mingw-w64-x86-64-win32'
  elif [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    extra+=' binutils-mingw-w64-x86-64'
  fi
  if false; then  # debian:testing dropped the wine package: https://tracker.debian.org/pkg/wine
    [[ "${CW_CONFIG:-}" != *'noWINE'* ]] && extra+=' wine64 wine'
  fi
  if [[ "${CW_CONFIG:-}" = *'x86'* ]]; then
    if [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ]; then
      extra+=' gcc-mingw-w64-i686-win32'
    elif [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
      extra+=' binutils-mingw-w64-i686'
    fi
    extra+=' wine32'
  fi
  # https://tracker.debian.org/pkg/osslsigncode
  extra+=' osslsigncode'
  if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ] && extra+=' g++-mingw-w64-x86-64-win32'
    extra+=' nasm'
    if [[ "${CW_CONFIG:-}" = *'x86'* ]]; then
      [ "${CW_LLVM_MINGW_ONLY:-}" != '1' ] && extra+=' g++-mingw-w64-i686-win32'
    fi
  fi
  extra+=' python3-pefile'
  [ -n "${DEPLOY_AGE_PASS:+1}" ] && extra+=' openssh-client'
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  [ -n "${CW_GCCSUFFIX:-}" ] || CW_GCCSUFFIX='-16'

  [ "${CW_TRURL_TEST:-}" = '1' ] && extra+=' python3'

  extra+=' checksec'

  x64=0; a64=0; r64=0
  [[ "${CW_CONFIG}" = *'a64'* || ! "${CW_CONFIG}" =~ (x64|r64) ]] && a64=1
  [[ "${CW_CONFIG}" = *'r64'* || ! "${CW_CONFIG}" =~ (a64|x64) ]] && r64=1
  [[ "${CW_CONFIG}" = *'x64'* || ! "${CW_CONFIG}" =~ (a64|r64) ]] && x64=1

  unamem="$(uname -m)"

  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    anycross=0
    [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && anycross=1
    [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && anycross=1
    [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && anycross=1
    [ "${anycross}" = 1 ] && extra+=' qemu-user-static'
  fi

  if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
    extra+=" gcc${CW_GCCSUFFIX}"
    [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && extra+=" gcc${CW_GCCSUFFIX}-aarch64-linux-gnu"
    [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu"
    [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && extra+=" gcc${CW_GCCSUFFIX}-x86-64-linux-gnu"
    if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
      extra+=" g++${CW_GCCSUFFIX}"
      [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && extra+=" g++${CW_GCCSUFFIX}-aarch64-linux-gnu"
      [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && extra+=" g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
      [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && extra+=" g++${CW_GCCSUFFIX}-x86-64-linux-gnu"
    fi
  else
    # ./my-pkg/usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.builtins-aarch64.a
    [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:arm64"
    [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:riscv64"
    [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && dl+=" libclang-rt${CW_CCSUFFIX}-dev:amd64"
  fi
  if [[ ( "${CW_CONFIG:-}" = *'awslc'* || "${CW_CONFIG:-}" = *'boringssl'* ) && "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra+=" libc++${CW_CCSUFFIX}-dev"
    [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && dl+=" libc++${CW_CCSUFFIX}-dev:arm64"
    [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && dl+=" libc++${CW_CCSUFFIX}-dev:riscv64"
    [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && dl+=" libc++${CW_CCSUFFIX}-dev:amd64"
  fi
  if [[ "${CW_CONFIG:-}" = *'musl'* ]]; then
    extra+=' musl musl-dev'
    [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && extra+=' musl:arm64 musl-dev:arm64'
    [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && extra+=' musl:riscv64 musl-dev:riscv64'
    [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && extra+=' musl:amd64 musl-dev:amd64'

    [[ "${CW_CONFIG:-}" = *'gcc'* ]] && extra+=" libgcc${CW_GCCSUFFIX}-dev"

    if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'openssl'* ]]; then
      # for awslc/boringssl 'linux/random.h', openssl 'secure-memory' feature requiring 'linux/mman.h'
      [[ "${unamem}" = 'aarch64' && "${a64}" = 1 ]] && extra+=' linux-headers-arm64'
      [[ "${unamem}" = 'riscv64' && "${r64}" = 1 ]] && extra+=' linux-headers-riscv64'
      [[ "${unamem}" = 'x86_64'  && "${x64}" = 1 ]] && extra+=' linux-headers-amd64'
    fi
  else  # glibc
    # FIXME: workaround for glibc-llvm-riscv64 builds:
    if [[ "${CW_CONFIG:-}" != *'gcc'* && "${r64}" = 1 ]]; then
      extra+=" gcc${CW_GCCSUFFIX}-riscv64-linux-gnu"
      if [[ "${CW_CONFIG:-}" = *'awslc'* ]] || [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
        extra+=" g++${CW_GCCSUFFIX}-riscv64-linux-gnu"
      fi
    fi
    [[ "${unamem}" != 'aarch64' && "${a64}" = 1 ]] && extra+=' libc6-dev-arm64-cross'
    [[ "${unamem}" != 'riscv64' && "${r64}" = 1 ]] && extra+=' libc6-dev-riscv64-cross'
    [[ "${unamem}" != 'x86_64'  && "${x64}" = 1 ]] && extra+=' libc6-dev-amd64-cross'

    anynoncross=0
    [[ "${unamem}" = 'aarch64' && "${a64}" = 1 ]] && anynoncross=1
    [[ "${unamem}" = 'riscv64' && "${r64}" = 1 ]] && anynoncross=1
    [[ "${unamem}" = 'x86_64'  && "${x64}" = 1 ]] && anynoncross=1
    [ "${anynoncross}" = 1 ] && extra+=' libc6-dev'
  fi

  [[ "${extra} ${dl}" = *':arm64'*   ]] && ${sudo} dpkg --add-architecture arm64
  [[ "${extra} ${dl}" = *':riscv64'* ]] && ${sudo} dpkg --add-architecture riscv64
  [[ "${extra} ${dl}" = *':amd64'*   ]] && ${sudo} dpkg --add-architecture amd64
fi

[[ ! "${CW_CONFIG}" =~ (zero|bldtst|nocookie) ]] && extra+=' python3'  # for libpsl

[ -n "${COSIGN_AGE_PASS:+1}" ] && extra+=' cosign'
[ -n "${MINISIGN_AGE_PASS:+1}" ] && extra+=' minisign'
[ -n "${SIGN_SSH_AGE_PASS:+1}" ] && extra+=' openssh-client'

[ -n "${SIGN_CODE_AGE_PASS:+1}${COSIGN_AGE_PASS:+1}${DEPLOY_AGE_PASS:+1}${MINISIGN_AGE_PASS:+1}${SIGN_PKG_AGE_PASS:+1}${SIGN_SSH_AGE_PASS:+1}" ] && extra+=' age'

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
    sha256sum --tag -- "${f}"
    dpkg-deb --contents "${f}"
    dpkg-deb --extract --verbose "${f}" my-pkg
  done
  if [ ! -d 'my-pkg/usr/lib/clang' ]; then
    ln -s -f "llvm${CW_CCSUFFIX}/lib/clang" 'my-pkg/usr/lib/clang'
  fi
  find -L 'my-pkg/usr/lib/clang' | sort
fi

if [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
  export CW_CCSUFFIX="${CW_GCCSUFFIX:-}"
fi

echo '=============='
find \
  /usr/lib/gcc-cross/riscv64-linux-gnu/16/include           \
  /usr/include/riscv64-linux-musl                           \
  /usr/riscv64-linux-gnu/include/c++/16                     \
  /usr/riscv64-linux-gnu/include/c++/16/backward            \
  /usr/riscv64-linux-gnu/include/c++/16/riscv64-linux-gnu   -name stdlib.h || true
echo '--------------'
find /usr -name stdlib.h || true
echo '--------------'

# musl-debian-testing-llvm
# /usr/include/aarch64-linux-musl/stdlib.h
# /usr/include/c++/15/stdlib.h
# /usr/include/c++/15/tr1/stdlib.h
# /usr/include/c++/16/stdlib.h
# /usr/include/c++/16/tr1/stdlib.h
# /usr/include/riscv64-linux-musl/stdlib.h
# /usr/include/x86_64-linux-musl/stdlib.h
# /usr/riscv64-linux-gnu/include/bits/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/16/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/16/tr1/stdlib.h
# /usr/riscv64-linux-gnu/include/stdlib.h
# /usr/x86_64-linux-gnu/include/bits/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/16/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/16/tr1/stdlib.h
# /usr/x86_64-linux-gnu/include/stdlib.h
# ->
# /usr/lib/llvm-22/lib/clang/22/include
# /usr/include/riscv64-linux-musl
# /usr/riscv64-linux-gnu/include/c++/16
# /usr/riscv64-linux-gnu/include/c++/16/backward
# /usr/riscv64-linux-gnu/include/c++/16/riscv64-linux-gnu

# musl-debian-stable-llvm
# /usr/lib/llvm-22/lib/clang/22/include/llvm_libc_wrappers/stdlib.h
# /usr/include/aarch64-linux-gnu/bits/stdlib.h
# /usr/include/aarch64-linux-musl/stdlib.h
# /usr/include/c++/14/stdlib.h
# /usr/include/c++/14/tr1/stdlib.h
# /usr/include/riscv64-linux-musl/stdlib.h
# /usr/include/stdlib.h
# /usr/include/x86_64-linux-musl/stdlib.h
# /usr/riscv64-linux-gnu/include/bits/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/14/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/14/tr1/stdlib.h
# /usr/riscv64-linux-gnu/include/stdlib.h
# /usr/x86_64-linux-gnu/include/bits/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/14/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/14/tr1/stdlib.h
# /usr/x86_64-linux-gnu/include/stdlib.h
# ->
# /usr/lib/llvm-22/lib/clang/22/include
# /usr/include/riscv64-linux-musl
# /usr/riscv64-linux-gnu/include/c++/14
# /usr/riscv64-linux-gnu/include/c++/14/backward
# /usr/riscv64-linux-gnu/include/c++/14/riscv64-linux-gnu

# musl-debian-testing-gcc
# /usr/include/aarch64-linux-gnu/bits/stdlib.h
# /usr/include/c++/16/stdlib.h
# /usr/include/c++/16/tr1/stdlib.h
# /usr/include/riscv64-linux-musl/stdlib.h
# /usr/include/stdlib.h
# /usr/include/x86_64-linux-musl/stdlib.h
# /usr/riscv64-linux-gnu/include/bits/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/16/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/16/tr1/stdlib.h
# /usr/riscv64-linux-gnu/include/stdlib.h
# /usr/x86_64-linux-gnu/include/bits/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/16/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/16/tr1/stdlib.h
# /usr/x86_64-linux-gnu/include/stdlib.h
# ->
# /usr/lib/gcc-cross/riscv64-linux-gnu/16/include
# /usr/include/riscv64-linux-musl
# /usr/riscv64-linux-gnu/include/c++/16
# /usr/riscv64-linux-gnu/include/c++/16/backward
# /usr/riscv64-linux-gnu/include/c++/16/riscv64-linux-gnu

# musl-debian-stable-gcc
# /usr/include/aarch64-linux-musl/stdlib.h
# /usr/include/x86_64-linux-musl/stdlib.h
# /usr/riscv64-linux-gnu/include/bits/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/14/stdlib.h
# /usr/riscv64-linux-gnu/include/c++/14/tr1/stdlib.h
# /usr/riscv64-linux-gnu/include/stdlib.h
# /usr/x86_64-linux-gnu/include/bits/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/14/stdlib.h
# /usr/x86_64-linux-gnu/include/c++/14/tr1/stdlib.h
# /usr/x86_64-linux-gnu/include/stdlib.h
# ->
# /usr/lib/gcc-cross/riscv64-linux-gnu/14/include
# /usr/include/riscv64-linux-musl

./_build.sh
