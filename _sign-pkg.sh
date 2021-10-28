#!/bin/sh

# Copyright 2020-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")" || exit 1

# Create signature for package
if [ -n "${SIGN_PKG_KEY_ID:-}" ] && \
   [ -n "${SIGN_PKG_KEY_PASS:+1}" ] && \
   gpg --list-public-keys "${SIGN_PKG_KEY_ID}" >/dev/null 2>&1; then
  file="$1"
  echo "Package signing: '${file}'"
  gpg --batch --yes --no-tty \
    --pinentry-mode loopback --passphrase-fd 0 \
    --keyid-format 0xlong \
    --detach-sign --armor --local-user "${SIGN_PKG_KEY_ID}" "${file}" <<EOF
${SIGN_PKG_KEY_PASS}
EOF
  touch -c -r "${file}" "${file}.asc"
fi
