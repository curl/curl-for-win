#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra="${extra} go nasm"

export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
time brew update >/dev/null
# shellcheck disable=SC2086
time brew install xz gnu-tar mingw-w64 llvm gettext \
                  jq dos2unix osslsigncode openssh wine-stable ${extra}
time wineboot --init

./_build.sh
