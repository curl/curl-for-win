#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-{x86_64,i686}-{clang,cmake,jq,python3-pip,rsync,gettext,osslsigncode} \
  zip

[[ "${APPVEYOR_REPO_BRANCH:-}" = *'boringssl'* ]] && \
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-{x86_64,i686}-{go,nasm}

./_build.sh
