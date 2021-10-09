#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md

[ "${CC}" = 'mingw-clang' ] && _optpkg='llvm'

export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
time brew update >/dev/null
time brew upgrade python
time brew install xz zstd gnu-tar mingw-w64 ${_optpkg} gettext \
                  jq dos2unix openssl@3 osslsigncode openssh
time brew install --cask wine-stable
time wineboot --init

./_build.sh
