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

# Strip '-built-on-*' suffix for the single-file artifact.
for f in ./*-*-mingw*.*; do
  new="$(echo "${f}" | sed 's|-built-on-[^.]*||g')"
  [ "${f}" = "${new}" ] || mv -f "${f}" "${new}"
done

sed 's|-built-on-[^.]*||g' hashes.txt | sort > hashes.txt.all
touch -r hashes.txt hashes.txt.all
mv -f hashes.txt.all hashes.txt

# Create an artifact that includes all packages
_ALL="all-mingw-${CURL_VER_}${_REV}.zip"
{
  ls -1 ./*-*-mingw*.*
  echo 'hashes.txt'
  echo "${_BLD}"
  echo "${_LOG}"
} | sort | \
zip --quiet -0 --strip-extra --names-stdin - > "${_ALL}"
zip --latest-time "${_ALL}"

openssl dgst -sha256 "${_ALL}" | tee    "${_ALL}.txt"
openssl dgst -sha512 "${_ALL}" | tee -a "${_ALL}.txt"

./_sign-pkg.sh "${_ALL}"

# Official deploy
if [ "${PUBLISH_PROD_FROM}" = "${_OS}" ] && \
   [ "${_BRANCH#*main*}" != "${_BRANCH}" ]; then

  # decrypt deploy key
  DEPLOY_KEY="$(realpath '.')/deploy.key"
  if [ -f "${DEPLOY_KEY}.asc" ]; then
  (
    set +x
    if [ -n "${DEPLOY_GPG_PASS}" ]; then
      install -m 600 /dev/null "${DEPLOY_KEY}"
      echo "${DEPLOY_GPG_PASS}" | gpg \
        --batch --yes --no-tty --quiet \
        --pinentry-mode loopback --passphrase-fd 0 \
        --decrypt "${DEPLOY_KEY}.asc" 2>/dev/null >> "${DEPLOY_KEY}"
    fi
  )
  fi

  if [ -s "${DEPLOY_KEY}" ]; then
  (
    set +x
    # add deploy target to known hosts
    # ssh-keyscan silly.haxx.se
    readonly host_key='silly.haxx.se ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFVVUP9dpjNl2qbHkDYMDS+cTOfxFytjkC04Oh9RNJBg'
    if [ ! -f "${HOME}/.ssh/known_hosts" ]; then
      mkdir -m 700 "${HOME}/.ssh"
      install -m 600 /dev/null "${HOME}/.ssh/known_hosts"
    fi
    if ! grep -q -a -F "${host_key}" -- "${HOME}/.ssh/known_hosts"; then
      echo "${host_key}" >> "${HOME}/.ssh/known_hosts"
    fi

    echo "Uploading: '${_ALL}'"
    rsync \
      --checksum \
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
  )
  fi

  case "${_OS}" in
    mac)   rm -f -P "${DEPLOY_KEY}";;
    linux) [ -w "${DEPLOY_KEY}" ] && srm "${DEPLOY_KEY}";;
  esac
  rm -f "${DEPLOY_KEY}"
fi
