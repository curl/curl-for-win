#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Merge unified packages made for different CPUs into a single
# one with universal macOS binaries supporting all these CPUs.

# Universal, per-OS package: Initialize
export _PKGSUFFIX_MACUNI="-universal-${_PKGOS}"
export _UNIPKG="curl-${CURL_VER_}${_REVSUFFIX}${_PKGSUFFIX_MACUNI}${_FLAV}"

# Universal, per-OS package: Build
export _NAM="${_UNIPKG}"
export _VER="${CURL_VER_}"
export _OUT="${_UNIPKG}"
export _BAS="${_UNIPKG}"
export _DST="${_UNIPKG}"

_ref='curl/CHANGES'

if [ ! -f "${_ref}" ]; then
  # This can happen with CW_BLD partial builds.
  echo '! WARNING: curl build missing. Skip packaging.'
else
  rm -r -f "${_UNIPKG:?}"
  mkdir -p "${_UNIPKG}"
  unipkg="${_UNIPKG}"
  rm -r -f __dirs__.txt
  find . -name '__macuni__.txt' | sort -u | while read -r f; do
    d="$(dirname "${f}")"  # get main directory, e.g. 'curl-8.0.0_1-aarch64-macos'
    echo "${d}" >> __dirs__.txt
    rsync --archive --update "${d}/" "${unipkg}"
  done
  rm -r -f "${unipkg}/__macuni__.txt"
  # Is it possible to merge .map files? Exclude them from universal packages for now.
  find "${unipkg}" -name '*.map' -delete
  # Walk through all executables and libraries we want to merge into universal.
  find "${unipkg}" -mindepth 2 -type f \( -name '*.a' -o -perm +111 \) | while read -r f; do
    sub="$(printf '%s' "${f}" | cut -c 2- | sed -E 's|^[^/]+||g')"  # get subdir part, e.g. '/lib/libname.a'
    in=()
    while read -r d; do
      in+=("${d}${sub}")
    done <<< "$(cat __dirs__.txt)"
    lipo -create -output "${f}" "${in[@]}"
    # TODO: code sign
    touch -r "${_ref}" "${f}"
  done
  rm -r -f __dirs__.txt
  ./_pkg.sh "${_ref}" 'macuni'
fi
