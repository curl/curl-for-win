#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  _BLDDIR='_bld'

  cmake -B "${_BLDDIR}"
  cmake --build "${_BLDDIR}"
  cmake --install "${_BLDDIR}" --prefix '_pkg'

  cp -f -p '_pkg/usr/local/bin/osslsigncode' ../osslsigncode-local
)
