#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Create a clickable desktop icon opening a URL

ref="$1"
fil="$2"
url="$3"

if [ "${_OS}" = 'win' ]; then
  _fn="${_DST}/${fil}.url"
  cat <<EOF | sed 's/$/\r/' > "${_fn}"
[InternetShortcut]
URL=${url}
EOF
elif [ "${_OS}" = 'mac' ]; then
  _fn="${_DST}/${fil}.webloc"
  cat <<EOF > "${_fn}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>URL</key>
  <string>${url}</string>
</dict>
</plist>
EOF
elif [ "${_OS}" = 'linux' ]; then
  # https://specifications.freedesktop.org/desktop-entry/latest/index.html
  _fn="${_DST}/${fil}.desktop"
  cat <<EOF > "${_fn}"
[Desktop Entry]
Type=Link
Name=${fil}
URL=${url}
EOF
else
  _fn="${_DST}/${fil}-URL.txt"
  echo "${url}" > "${_fn}"
fi

touch -c -r "${ref}" "${_fn}"
