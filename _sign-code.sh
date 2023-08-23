#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# TODO: add support for code signing Unixy binaries
#       E.g. 'codesign' for mac.
#       Linux: https://stackoverflow.com/questions/1732927/signed-executables-under-linux
if [ "${_OS}" = 'win' ] && \
   [ -s "${SIGN_CODE_KEY}" ] && \
   [ -n "${SIGN_CODE_KEY_PASS:+1}" ]; then

  _ref="$1"
  shift

  case "${_HOSTOS}" in
    bsd|mac) unixts="$(TZ=UTC stat -f '%m' "${_ref}")";;
    *)       unixts="$(TZ=UTC stat --format='%Y' "${_ref}")";;
  esac

  # Add code signature
  for file in "$@"; do
    echo "Code signing: '${file}'"
    # Requires: osslsigncode 2.4 or newer
    # -ts 'https://freetsa.org/tsr'
    osslsigncode sign \
      -h sha512 \
      -in "${file}" -out "${file}-signed" \
      -time "${unixts}" \
      -pkcs12 "${SIGN_CODE_KEY}" -readpass /dev/stdin <<EOF
${SIGN_CODE_KEY_PASS}
EOF
  # # Create detached code signature:
  # osslsigncode extract-signature \
  #   -in  "${file}-signed" \
  #   -out "${file}.p7"
    cp -f "${file}-signed" "${file}"
    rm -f "${file}-signed"
  done
fi
