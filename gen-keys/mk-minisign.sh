#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install minisign age
#   pip install base58

readonly base="$1"
readonly revi="$2"
readonly prfx="${base}_${revi}-minisign"

install -m 600 /dev/null "${prfx}.password"; key_pass="$(openssl rand 32 | base58 | tee -a "${prfx}.password")"

printf "%s\n%s\n" "${key_pass}" "${key_pass}" | minisign -G -p "${prfx}.pub" -s "${prfx}.key"

# Encrypt private key once again, for distribution (ASCII, binary)
age-keygen      --output="${prfx}.key.age.key"
age --encrypt --identity="${prfx}.key.age.key" --armor "${prfx}.key" > "${prfx}.key.age.asc"
