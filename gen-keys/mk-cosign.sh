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
  o="$1"; rm -f -- "$o"; install -m 600 /dev/null "$o"; shift
  (
    "$@"
  ) >> "$o"
}

case "$(uname)" in
  *Darwin*)
    MY_GPG="$(brew --prefix)/opt/gnupg/bin/gpg";;
  *)
    MY_GPG='gpg';;
esac

my_gpg() {
  "${MY_GPG}" --full-timestrings "$@"
}

readonly base="$1"
readonly revi="$2"

readonly prfx="${base}_${revi}"

cosign_pass="$(openssl rand 32 | base58)"; readonly cosign_pass
privout "${prfx}-cosign.password" \
printf '%s' "${cosign_pass}"

export COSIGN_PASSWORD="${cosign_pass}"
cosign generate-key-pair

encr_pass="$(openssl rand 32 | base58)"; readonly encr_pass
privout "${prfx}-cosign-private_gpg.password" \
printf '%s' "${encr_pass}"

# Encrypted .p12 for distribution (ASCII, binary)
echo "${encr_pass}" | gpg --batch --verbose --yes --no-tty \
  --pinentry-mode loopback --passphrase-fd 0 \
  --force-ocb \
  --cipher-algo aes256 --digest-algo sha512 --compress-algo none \
  --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
  --symmetric --no-symkey-cache --output 'cosign.key.asc' --armor \
  --set-filename '' 'cosign.key'

gpg --batch --dearmor < 'cosign.key.asc' > 'cosign.key.gpg'
