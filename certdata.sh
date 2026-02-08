#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  # Make steps for determinism

  readonly _ref="${_CERTDATA}"

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}"

  # Sadly there do not seem to be a copy of this license within the certdata
  # (Firefox) repository, that we could download from the same commit hash
  # as certdata itself. (only some _almost_ identical copies.)
  # To avoid depending on an unversioned download (or vendoring this file),
  # link to it instead:
  ../_mk-url-file.sh "${_ref}" 'LICENSE' 'https://www.mozilla.org/media/MPL/2.0/index.txt'

  ../_pkg.sh "$(pwd)/${_ref}"
)
