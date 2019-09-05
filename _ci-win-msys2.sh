#!/usr/bin/env bash

# Copyright 2016-2018 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

pacman --noconfirm --ask 20 --noprogressbar -S --needed \
  mc
pacman --noconfirm --ask 20 --noprogressbar -S -yu -u
pacman --noconfirm --ask 20 --noprogressbar -S -yu -u
pacman --noconfirm --ask 20 --noprogressbar -S --needed \
  mingw-w64-{i686,x86_64}-{cmake,jq,python3-pip} \
  zip

[ "${CC}" = 'mingw-clang' ] && \
pacman --noconfirm --ask 20 --noprogressbar -S --needed \
  mingw-w64-{i686,x86_64}-clang

./_build.sh
