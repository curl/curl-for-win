#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

env='x86_64'

pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-"${env}"-{clang,cmake,ninja,jq,python-pefile,rsync,gettext,osslsigncode} \
  zip

[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && \
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-"${env}"-go

if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
  pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
    mingw-w64-"${env}"-nasm
fi

./_build.sh
