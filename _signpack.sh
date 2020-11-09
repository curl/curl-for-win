#!/bin/sh

# Copyright 2020-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

cd "$(dirname "$0")" || exit

# Create signature for package
if [ "${PACKSIGN_KEY_ID}" ]; then
(
  set +x
  file="$1"
  echo "Package signing: '${file}'"
  echo "${PACKSIGN_KEY_PASS}" | \
  gpg \
    --batch --yes --no-tty \
    --pinentry-mode loopback --passphrase-fd 0 \
    --keyid-format 0xlong \
    --detach-sign --armor --local-user "${PACKSIGN_KEY_ID}" "${file}"
)
fi
