#!/usr/bin/env bash

# Copyright 2016-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --refresh --sysupgrade --sysupgrade
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-{i686,x86_64}-{cmake,jq,python3-pip} \
  zip zstd

[ "${CC}" = 'mingw-clang' ] && \
pacman --noconfirm --ask 20 --noprogressbar --sync --needed \
  mingw-w64-{i686,x86_64}-clang

./_build.sh
