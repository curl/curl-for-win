#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  cmake -B _bld

  make --directory=_bld --jobs="${_JOBS}" install "DESTDIR=$(pwd)/install"

  cp -f -p "$(pwd)/install/usr/local/bin/osslsigncode" ../osslsigncode-local
)
