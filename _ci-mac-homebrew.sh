#!/bin/sh

# Copyright 2017-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

[ "${CC}" = 'mingw-clang' ] && _optpkg='llvm'

export HOMEBREW_NO_AUTO_UPDATE=1
time brew update >/dev/null
time brew upgrade python
time brew install xz zstd gnu-tar mingw-w64 ${_optpkg} \
                  jq dos2unix gnu-sed openssl@1.1
time brew cask install wine-stable
time wineboot --init

./_build.sh
