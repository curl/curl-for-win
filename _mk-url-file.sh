#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Create a clickable desktop icon opening a URL

ref="$1"
nam="$2"
url="$3"

if [ "${_OS}" = 'win' ]; then
  _fn="${_DST}/${nam}.url"
  cat <<EOF | sed 's/$/\r/' > "${_fn}"
[InternetShortcut]
URL=${url}
EOF
elif [ "${_OS}" = 'mac' ]; then
  _fn="${_DST}/${nam}.webloc"
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
  _fn="${_DST}/${nam}.desktop"
  cat <<EOF > "${_fn}"
[Desktop Entry]
Type=Link
Name=${nam}
URL=${url}
EOF
else
  _fn="${_DST}/${nam}-URL.txt"
  echo "${url}" > "${_fn}"
fi

touch -c -r "${ref}" "${_fn}"
