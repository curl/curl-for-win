#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install cosign
#   pip install base58

# Redirect stdout securely to non-world-readable files
privout() {
  o="$1"; rm -f "$o"; install -m 600 /dev/null "$o"; shift
  (
    "$@"
  ) >> "$o"
}

readonly base="$1"
readonly revi="$2"

readonly prfx="${base}_${revi}"

cosign_pass="$(openssl rand 32 | base58)"; readonly cosign_pass
privout "${prfx}-cosign.password" \
printf '%s' "${cosign_pass}"

export COSIGN_PASSWORD="${cosign_pass}"
cosign generate-key-pair
