#!/bin/sh

# Copyright 2018-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

sort "${_BLD}" > "${_BLD}.sorted"
mv -f "${_BLD}.sorted" "${_BLD}"

# Use the newest package timestamp for supplementary files
# shellcheck disable=SC2012
touch -r "$(ls -1 -t ./*-*-mingw*.* | head -1)" hashes.txt "${_BLD}" "${_LOG}"

ls -l ./*-*-mingw*.*
cat hashes.txt
cat "${_BLD}"

# TODO: Move adding ${_REV} to the filename into _pack.sh.

# Strip '-built-on-*' suffix for the single-file artifact,
# and also add revision to filenames.
for f in ./*-*-mingw*.*; do
  mv -f "${f}" "$(echo "${f}" | sed "s|-win|${_REV}-win|g" | sed 's|-built-on-[^.]*||g')"
done

sed "s|-win|${_REV}-win|g" hashes.txt | sed 's|-built-on-[^.]*||g' | sort > hashes.txt.all
touch -r hashes.txt hashes.txt.all
mv -f hashes.txt.all hashes.txt

# Create an artifact that includes all packages
_ALL="all-mingw-${CURL_VER_}${_REV}.zip"
{
  ls -l ./*-*-mingw*.*
  echo 'hashes.txt'
  echo "${_BLD}"
  echo "${_LOG}"
} | sort | \
zip --quiet -0 -X -@ - > "${_ALL}"
zip --latest-time "${_ALL}"

openssl dgst -sha256 "${_ALL}" | tee    "${_ALL}.txt"
openssl dgst -sha512 "${_ALL}" | tee -a "${_ALL}.txt"

./_signpack "${_ALL}"

# Official deploy
if [ "${_BRANCH#*master*}" != "${_BRANCH}" ] && \
   [ "${PUBLISH_PROD_FROM}" = "${_OS}" ]; then
(
  set +x
  if [ -f "${DEPLOY_KEY}" ]; then
    echo "Uploading: '${_ALL}'"
    rsync \
      --archive \
      --rsh "ssh \
        -i '${DEPLOY_KEY}' \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=5" \
      "${_ALL}" \
      "${_ALL}.asc" \
      "${_ALL}.txt" \
      'curl-for-win@silly.haxx.se:.'
  fi
)
fi
