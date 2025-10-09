#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

extra='cosign gnu-tar jq'
[[ "${CW_CONFIG:-}" = *'boringssl'* ]] && extra+=' go'
if [[ "${CW_CONFIG:-}" != *'mac'* ]] || [[ "${CW_CONFIG:-}" = *'llvm'* ]]; then
  extra+=' llvm lld'
fi

if [[ "${CW_CONFIG:-}" = *'win'* ]]; then
  extra+=' mingw-w64 osslsigncode openssh'
  # On AppVeyor CI macos-sonoma runner wine stalls for 5 minutes 5 times with
  # this error on first invocation (from this script). Then on a next invocation
  # it repeats the 5-minute stalls indefinitely. Skip wine as a workaround:
  [ -z "${APPVEYOR_ACCOUNT_NAME:-}" ] && extra+=' wine-stable'
  if [[ "${CW_CONFIG:-}" = *'boringssl'* ]] || [[ "${CW_CONFIG:-}" = *'awslc'* ]]; then
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
  brew install --quiet ${extra}
fi

if [[ "${CW_CONFIG:-}" = *'win'* ]] && command -v wine >/dev/null 2>&1; then
  # https://gitlab.winehq.org/wine/wine/-/wikis/FAQ#how-do-i-disable-the-gui-crash-dialog
  wine reg add 'HKCU\Software\Wine\WineDbg' -v 'ShowCrashDialog' -t REG_DWORD -d 0 -f
fi

./_build.sh
