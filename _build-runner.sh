#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# EXPERIMENTAL

# This script makes a local curl (and dependencies) build.
# Start it in a curl-for-win repo sandbox.
# Output is generated in the same directory.

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

# Customize these
export CW_CONFIG='dev-x64-big-cares'
#export CURL_REV_='master'
#CURL_SCRIPT='curl-cmake'  # curl-gnumake (default) or curl-cmake or curl-autotools

# Install necessary packages
if [ ! -f .cw-initialized ]; then
  extra=''
  case "$(uname)" in
    *_NT*)
      pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
        mingw-w64-x86_64-{clang,cmake,jq,python-pefile,rsync,gettext,osslsigncode} \
        zip
      [[ "${CW_CONFIG:-}" = *'boringssl'* ]] && \
      pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
        mingw-w64-x86_64-{go,nasm}
      ;;
    Linux*)
      if [ "${_HOSTOS}" = 'linux' ] && [ -s /etc/os-release ]; then
        _DIST="$(grep -a '^ID=' /etc/os-release | cut -c 4- | tr -d '"' || true)"
        _DIST="${_DIST:-unrecognized}"
      fi

      if [ "${_DIST}" = 'debian' ]; then
        [[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} golang nasm"
        [[ "${CW_CONFIG:-}" = *'musl'* ]] && extra="${extra} musl musl-dev musl-tools"
        if [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
          extra="${extra} checksec"
        fi
        # shellcheck disable=SC2086
        apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
          curl git gpg rsync python3-pefile make cmake \
          autoconf automake autopoint libtool \
          zip time jq dos2unix secure-delete ${extra}
      elif [ "${_DIST}" = 'alpine' ]; then
        [[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} go nasm"
        if [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
          apk add --no-cache checksec-rs --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing/
        fi
        # shellcheck disable=SC2086
        apk add --no-cache curl git gpg rsync build-base cmake \
          autoconf automake libtool \
          tar xz jq dos2unix openssl ${extra}
      fi
      ;;
    Darwin*)
      [[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} go nasm"
      # shellcheck disable=SC2086
      brew install \
        xz gnu-tar gettext jq dos2unix ${extra}
      ;;
  esac
  touch .cw-initialized
fi

# Not much to customize here
export CW_LLVM_MINGW_DL=1
export CW_LLVM_MINGW_ONLY=1
export CW_NOTIME=1
export CW_MAP=1
export CW_JOBS=2

export VIRUSTOTAL_APIKEY=
export SIGN_CODE_GPG_PASS=
export SIGN_CODE_KEY_PASS=
export SIGN_PKG_KEY_ID=
export SIGN_PKG_GPG_PASS=
export SIGN_PKG_KEY_PASS=
export DEPLOY_GPG_PASS=
export DEPLOY_KEY_PASS=

# Run
[ -n "${CURL_SCRIPT:-}" ] && ln -s -f "${CURL_SCRIPT}.sh" 'curl.sh'

./_build.sh 2>&1 | stdbuf -i0 -o0 -e0 tee "log-$(date '+%s').txt"
