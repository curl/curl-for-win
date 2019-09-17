#!/bin/sh

# Copyright 2017-2019 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

[ "${CC}" = 'mingw-clang' ] && _optpkg='llvm'

export HOMEBREW_NO_AUTO_UPDATE=1
time brew update >/dev/null
time brew upgrade python3
time brew install xz gnu-tar mingw-w64 ${_optpkg} \
                  jq dos2unix gnu-sed openssl@1.1
time brew install --force-bottle --build-bottle wine
time wineboot --init

./_build.sh
