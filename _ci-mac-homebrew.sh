#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

extra=''
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' go'
if [[ "${CW_CONFIG:-}" != *'mac'* ]] || [[ "${CW_CONFIG:-}" != *'gcc'* ]]; then
  extra+=' llvm lld'
fi

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra+=' mingw-w64 osslsigncode wine-stable openssh'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]]; then
    extra+=' nasm'
  fi
elif [[ "${CW_CONFIG:-}" = *'linux'* ]]; then
  extra+=' filosottile/musl-cross/musl-cross'
elif [[ "${CW_CONFIG:-}" = *'mac'* ]] && [[ "${CW_CONFIG:-}" = *'gcc'* ]]; then
  extra+=' gcc'
fi

if [ -n "${extra}" ]; then
  export HOMEBREW_NO_AUTO_UPDATE=1
  export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1
  export HOMEBREW_NO_ANALYTICS=1
  export HOMEBREW_NO_ANALYTICS_MESSAGE_OUTPUT=1
  brew update >/dev/null || true
  # shellcheck disable=SC2086
  # Using `|| true` to avoid failing due to preinstalled non-Homebrew
  # python3: `Could not symlink bin/2to3`
  brew install ${extra} || true
fi

[[ "${CW_CONFIG:-}" = *'win'* ]] && wineboot --init

./_build.sh
