#!/bin/sh

# Copyright 2022-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Normalize object names inside an .a library, to create reproducible
# output across build systems:
#   - strip `libname_la-` prefix added by autotools
#   - change suffix to .o / .res
#   - alpha-sort
#
# NOTE: This script does not support spaces in filenames.

while [ "${1#--*}" != "${1:-}" ]; do
  if [ "$1" = '--ar' ]; then
    shift; AR="$1"
  fi
done

[ -z "${AR:-}" ] && exit 1

while [ -n "${1:-}" ]; do
  f="$1"; shift
  # Process .a files only, except .dll.a ones.
  if [ "${f#*.a}" != "${f}" ] && \
     [ "${f#*.dll.a}" = "${f}" ]; then
    echo "! Normalizing library: '${f}'"
    tmp="$(mktemp -d)"
    ff="$(realpath "${f}")"
    (
      cd "${tmp}"
      "${AR}" x "${ff}"  # --output= option supported since llvm-ar 15.0.0. TODO: use it.
    )
    for o in "${tmp}"/*; do
      n="$(printf '%s' "${o}" | sed -E \
        -e 's/lib[a-z0-9]+_la-//g' \
        -e 's/(\.cc\.obj|\.c\.obj|\.obj)$/.o/g' \
        -e 's/\.rc\.res/.res/g')"
      [ "${o}" != "${n}" ] && mv -n "${o}" "${n}"
    done
    rm "${f}"
    # shellcheck disable=SC2046
    "${AR}" crD "${f}" $(find "${tmp}" -type f | sort)
    rm -r -f "${tmp}"
  fi
done
