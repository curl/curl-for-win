#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install diffutils  # for cmp
#   pip install base58

# GPG-encrypted key for distribution (ASCII)
# Show default --s2k-count rounds:
#   $ gpg-connect-agent 'GETINFO s2k_count_cal' /bye
enc_gpg() {
  echo "$2" | gpg --batch --verbose --yes \
    --pinentry-mode loopback --passphrase-fd 0 \
    --force-ocb \
    --cipher-algo aes256 --digest-algo sha512 --compress-algo none \
    --s2k-cipher-algo aes256 --s2k-digest-algo sha512 --s2k-count 65011712 \
    --symmetric --no-symkey-cache --output "$1.asc" --armor \
    --set-filename '' "$1"
}

# Deploy key for CI script (restricted)
key='id-curl-for-win-deploy'

install -m 600 /dev/null "${key}.password"    ; key_pass="$(openssl rand 32 | base58 | tee -a "${key}.password")"
install -m 600 /dev/null "${key}.asc.password"; gpg_pass="$(openssl rand 32 | base58 | tee -a "${key}.asc.password")"; readonly gpg_pass

rm -f "${key}"; ssh-keygen -N "${key_pass}" -a 192 -t ed25519 -f "${key}" -C "${key}"; enc_gpg "${key}" "${gpg_pass}"

# Verify and copy to final filename
if echo "${gpg_pass}" | gpg \
     --batch \
     --pinentry-mode loopback --passphrase-fd 0 \
     --decrypt "${key}.asc" | \
   cmp --quiet -- "${key}" -; then
  cp -p "${key}.asc" 'deploy.key.asc'
fi

age-keygen      --output="${key}.age.key"
age --encrypt --identity="${key}.age.key" --armor "${key}" > "${key}.age.asc"
age --encrypt --identity="${key}.age.key"         "${key}" > "${key}.age"
