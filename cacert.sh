#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  # Make steps for determinism

  readonly _ref="${_CACERT}"

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/bin"

  # To avoid depending on yet another unversioned download (or vendoring
  # the license), link to it instead:
  _fn="${_DST}/LICENSE.url"
  cat <<EOF > "${_fn}"
[InternetShortcut]
URL=https://www.mozilla.org/media/MPL/2.0/index.txt
EOF
  unix2dos --quiet --keepdate "${_fn}"
  touch -c -r "${_ref}" "${_fn}"

  cp -f -p "${_CACERT}" "${_DST}/bin/curl-ca-bundle.crt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
