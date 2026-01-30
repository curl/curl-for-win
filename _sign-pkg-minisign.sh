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
  echo "${MINISIGN_KEY_PASS}" | minisign -S -s "${MINISIGN_KEY}" -m "${file}" # => "${file}.minisign"
fi
