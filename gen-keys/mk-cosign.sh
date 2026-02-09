#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install cosign age pwgen

readonly base="$1"
readonly revi="$2"
readonly prfx="${base}_${revi}-cosign"

install -m 600 /dev/null "${prfx}.password"; key_pass="$(pwgen --secure 42 1 | tee -a "${prfx}.password")"

COSIGN_PASSWORD="${key_pass}" cosign generate-key-pair
mv cosign.key "${prfx}.key"
mv cosign.pub "${prfx}.pub"

# Encrypt private key once again, for distribution (ASCII, binary)
age-keygen      --output="${prfx}.key.age.key"
age --encrypt --identity="${prfx}.key.age.key" --armor "${prfx}.key" > "${prfx}.key.age.asc"
