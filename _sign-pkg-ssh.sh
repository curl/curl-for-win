#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

# Create signature for package
if [ -n "${SIGN_SSH_KEY:-}" ] && \
   [ -s "${SIGN_SSH_KEY}" ] && \
   [ -n "${SIGN_SSH_KEY_PASS:+1}" ]; then
  file="$1"
  echo "Package signing with ssh-keygen: '${file}'"
  unset DISPLAY
  export SSH_ASKPASS_REQUIRE='force'
  export SSH_ASKPASS; SSH_ASKPASS="$(pwd)/_sign-pkg-ssh-askpass.sh"
  rm -f "${file}".sig  # to avoid interactive question
  ssh-keygen -Y sign -n 'file' -f "${SIGN_SSH_KEY}" "${file}"
fi
