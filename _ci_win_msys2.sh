#!/usr/bin/env bash

# Copyright 2016-2018 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

[ "${CC}" = 'mingw-clang' ] && _optpkg='mingw-w64-{i686,x86_64}-clang'

pacman --noconfirm --ask 20 --noprogressbar -S --needed mc
pacman --noconfirm --ask 20 --noprogressbar -S -yu -u
pacman --noconfirm --ask 20 --noprogressbar -S -yu -u
pacman --noconfirm --ask 20 --noprogressbar -S --needed \
  zip mingw-w64-{i686,x86_64}-{cmake,jq,osslsigncode,python3-pip} ${_optpkg}

./_build.sh
