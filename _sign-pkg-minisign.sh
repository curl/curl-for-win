#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

# Create signature for package
if [ -n "${MINISIGN_KEY:-}" ] && \
   [ -s "${MINISIGN_KEY}" ] && \
   [ -n "${MINISIGN_KEY_PASS:+1}" ]; then
  file="$1"
  echo "Package signing with minisign: '${file}'"
  # Signature saved to "${file}.minisign"
  # The -l option is able to create signatures compatible with signify,
  # but it is not recommended by the minisign documentation.
  # https://jedisct1.github.io/minisign/
  minisign -S -s "${MINISIGN_KEY}" -m "${file}" <<EOF
${MINISIGN_KEY_PASS}
EOF
fi
