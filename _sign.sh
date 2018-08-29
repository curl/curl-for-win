#!/bin/sh

# Copyright 2016-2017 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

if [ -f "${CODESIGN_KEY}" ] && \
   ls "$(dirname "$0")/osslsigncode-determ"* > /dev/null 2>&1; then

  # Add code signature
  for file in $1; do
  (
    set +x
    # -ts 'http://timestamp.digicert.com'
    "$(dirname "$0")/osslsigncode-determ" sign -h sha256 \
      -in "${file}" -out "${file}-signed" \
      -pkcs12 "${CODESIGN_KEY}" -pass "${CODESIGN_KEY_PASS}"
    mv -f "${file}-signed" "${file}"
  )
  done
fi
