#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

# Create signature for package
if [ -n "${COSIGN_KEY:-}" ] && \
   [ -s "${COSIGN_KEY}" ] && \
   [ -n "${COSIGN_KEY_PASS:+1}" ]; then
  file="$1"
  echo "Package signing with cosign: '${file}'"
  tr -d '\n' <<EOF | \
  cosign sign-blob --yes --key="${COSIGN_KEY}" --new-bundle-format=true --bundle="${file}".sigstore "${file}"
${COSIGN_KEY_PASS}
EOF
  chmod 0644 "${file}".sigstore  # cosign creates it with 0600
fi
