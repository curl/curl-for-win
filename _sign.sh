#!/bin/sh

# Copyright 2016-2017 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

if [ -f "${CODESIGN_KEY}" ]; then
  # Add code signature
  for file in $1; do
  (
    set +x
    osslsigncode sign -h sha256 -in "${file}" -out "${file}-signed" \
      -pkcs12 "${CODESIGN_KEY}" -pass "${CODESIGN_KEY_PASS}" \
      -ts 'http://timestamp.digicert.com'
    mv -f "${file}-signed" "${file}"
  )
  done
fi
