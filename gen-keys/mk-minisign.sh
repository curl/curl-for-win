#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install minisign age
#   pip install base58

# Redirect stdout securely to non-world-readable files
privout() {
  o="$1"; rm -f -- "$o"; install -m 600 /dev/null "$o"; shift
  (
    "$@"
  ) >> "$o"
}

readonly base="$1"
readonly revi="$2"

readonly prfx="${base}_${revi}"

minisign_pass="$(openssl rand 32 | base58)"; readonly minisign_pass
privout "${prfx}-minisign.password" \
printf '%s' "${minisign_pass}"

printf "%s\n%s\n" "${minisign_pass}" "${minisign_pass}" | \
minisign -G -p "${prfx}-minisign.pub" -s "${prfx}-minisign.key"

age-keygen      --output="${prfx}-minisign.key.age.key"
age --encrypt --identity="${prfx}-minisign.key.age.key" --armor "${prfx}-minisign.key" > "${prfx}-minisign.key.age.asc"
age --encrypt --identity="${prfx}-minisign.key.age.key"         "${prfx}-minisign.key" > "${prfx}-minisign.key.age"
