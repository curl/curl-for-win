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
  # TODO: use `--signing-algorithm=ecdsa-sha2-512-nistp521` (with possibly
  #       a newer/better algo) option in the future, when it makes sense.
  #       https://blog.trailofbits.com/2026/01/29/building-cryptographic-agility-into-sigstore/
  #       https://github.com/sigstore/cosign/pull/3497/files
  #       https://github.com/sigstore/cosign/commit/8e7e0571a0ccad90a883da3676562eb6e1fe5ab4
  #       Supported by cosign v3.0.3+
  tr -d '\n' <<EOF | \
  cosign sign-blob --yes --key="${COSIGN_KEY}" --new-bundle-format=true --bundle="${file}".sigstore "${file}"
${COSIGN_KEY_PASS}
EOF
  chmod 0644 "${file}".sigstore  # cosign creates it with 0600
fi
