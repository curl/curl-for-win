#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install age diffutils  # for cmp
#   pip install base58

# Deploy key for CI script (restricted)
key='id-curl-for-win-deploy'

install -m 600 /dev/null "${key}.password"; key_pass="$(openssl rand 32 | base58 | tee -a "${key}.password")"

rm -f "${key}"; ssh-keygen -N "${key_pass}" -a 192 -t ed25519 -f "${key}" -C "${key}"

# Encrypt private key once again, for distribution (ASCII, binary)
age-keygen      --output="${key}.age.key"
age --encrypt --identity="${key}.age.key" --armor "${key}" > "${key}.age.asc"

if age --decrypt --identity="${key}.age.key" "${key}.age.asc" | cmp --quiet -- "${key}" -; then
  cp -p "${key}.age.asc" 'deploy.key.asc'
fi
