#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} go nasm"
[[ "${CW_CONFIG:-}" = *'win'* ]] && extra="${extra} mingw-w64 osslsigncode wine-stable openssh"

export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
brew update >/dev/null
# shellcheck disable=SC2086
brew install coreutils llvm dos2unix ${extra}

[[ "${CW_CONFIG:-}" = *'win'* ]] && wineboot --init

./_build.sh
