#!/usr/bin/env bash

# Copyright 2016-present Viktor Szakats. See LICENSE.md

set -euxo pipefail

export _CCSUFFIX=''

pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-{x86_64,i686}-{cmake,jq,python3-pip,rsync,gettext,osslsigncode} \
  zip zstd

[ "${CC}" = 'mingw-clang' ] && \
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-{x86_64,i686}-clang

./_build.sh
