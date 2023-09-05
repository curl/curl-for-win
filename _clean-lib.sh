#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Normalize object names inside an .a library, to create reproducible
# output across build systems:
#   - strip `libname_la-` prefix added by autotools
#   - change suffix to .o
#   - alpha-sort
#   - optionally strip objects when called with `--strip <strip-tool>`
#
# NOTE: This script does not support spaces in filenames.

strip=''

while [ "${1#--*}" != "${1:-}" ]; do
  if [ "$1" = '--ar' ]; then
    shift; AR="$1"; shift
  elif [ "$1" = '--strip' ]; then
    shift; strip="$1"; shift
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
    "${AR}" x --output="${tmp}" "${f}"  # --output= option requires llvm-ar v15.0.0 or binutils
    for o in "${tmp}"/*; do
      n="$(printf '%s' "${o}" | sed -E \
        -e 's/lib[a-z0-9]+_la-//g' \
        -e 's/(\.cc\.obj|\.c\.obj|\.obj)$/.o/g')"
      [ "${o}" != "${n}" ] && mv -n "${o}" "${n}"
    done
    # shellcheck disable=SC2086
    [ -n "${strip}" ] && "${strip}" ${_STRIPFLAGS_LIB:-} "${tmp}"/*
    rm "${f}"
    # shellcheck disable=SC2046
    "${AR}" crD "${f}" $(find "${tmp}" -type f | sort)
    rm -r -f "${tmp:?}"
  fi
done
