#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

sort -u "${_BLD}" > "${_BLD}.sorted"
mv -f "${_BLD}.sorted" "${_BLD}"

sort -u "${_URLS}" > "${_URLS}.sorted"
mv -f "${_URLS}.sorted" "${_URLS}"

if ! ls ./*-*-"${_PKGOS}"*.* >/dev/null 2>&1; then
  echo '! WARNING: Nothing to deploy.'
  exit 0
fi

# Use the newest package timestamp for supplementary files
# shellcheck disable=SC2012
touch -r "$(ls -1 -t ./*-*-"${_PKGOS}"*.* | head -n 1)" hashes.txt "${_BLD}" "${_URLS}" "${_LOG}"

find . -maxdepth 1 -type f -name "*-*-${_PKGOS}*.*" | sort
cat hashes.txt
cat "${_BLD}"
cat "${_URLS}"

# Strip '-built-on-*' suffix for the single-file artifact.
find . -maxdepth 1 -type f -name "*-*-${_PKGOS}*.*" | sort | while read -r f; do
  # shellcheck disable=SC2001
  new="$(echo "${f}" | sed 's/-built-on-[^.]*//g')"
  [ "${f}" = "${new}" ] || mv -f "${f}" "${new}"
done

sed 's/-built-on-[^.]*//g' hashes.txt | sort > hashes.txt.all
touch -r hashes.txt hashes.txt.all
mv -f hashes.txt.all hashes.txt

# Create an artifact that includes all packages
_ALL="all-${_PKGOS}-${CURL_VER_}${_REVSUFFIX}${_FLAV}.zip"
{
  find . -maxdepth 1 -type f \( -name "*-*-${_PKGOS}*.*" -o -name "*-version-*.txt" \) | sort
  echo 'hashes.txt'
  echo "${_BLD}"
  echo "${_URLS}"
  echo "${_LOG}"
} | sort | \
TZ=UTC zip --quiet -0 --strip-extra --names-stdin - > "${_ALL}"
TZ=UTC zip --latest-time "${_ALL}"

openssl dgst -sha256 "${_ALL}" | sed 's/^SHA256/SHA2-256/g' | tee "${_ALL}.txt"
touch -c -r "${_ALL}" "${_ALL}.txt"

./_sign-pkg.sh "${_ALL}"
./_sign-pkg-cosign.sh "${_ALL}"

# Official deploy
DEPLOY_KEY="$(pwd)/deploy.key"
if [ "${PUBLISH_PROD_FROM}" = "${_HOST}" ] && \
   [[ "${_CONFIG}" = *'main'* ]] && \
   [ -s "${DEPLOY_KEY}.asc" ] && \
   [ -n "${DEPLOY_GPG_PASS:+1}" ]; then

  # decrypt deploy key
  install -m 600 /dev/null "${DEPLOY_KEY}"
  gpg --batch --yes --no-tty --quiet \
    --pinentry-mode loopback --passphrase-fd 0 \
    --decrypt "${DEPLOY_KEY}.asc" 2>/dev/null >> "${DEPLOY_KEY}" <<EOF || true
${DEPLOY_GPG_PASS}
EOF

  if [ -s "${DEPLOY_KEY}" ]; then

    # add deploy target to known hosts
    # ssh-keyscan silly.haxx.se
    readonly host_key='silly.haxx.se ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFVVUP9dpjNl2qbHkDYMDS+cTOfxFytjkC04Oh9RNJBg'
    if [ ! -f "${HOME}/.ssh/known_hosts" ]; then
      [ -d "${HOME}/.ssh" ] || mkdir -m 700 "${HOME}/.ssh"
      ls -l "${HOME}/.ssh"
      install -m 600 /dev/null "${HOME}/.ssh/known_hosts"
    fi
    if ! grep -q -a -F "${host_key}" -- "${HOME}/.ssh/known_hosts"; then
      echo "${host_key}" >> "${HOME}/.ssh/known_hosts"
    fi

    # Requires: OpenSSH 8.4+ (2020-09-27)
    unset DISPLAY
    export SSH_ASKPASS_REQUIRE='force'
    export SSH_ASKPASS; SSH_ASKPASS="$(pwd)/_ul-askpass.sh"

    echo "Uploading: '${_ALL}'"
    # Sent command: rsync --server -tce.LsfxCIvu . .
    rsync \
      --checksum \
      --times \
      --no-compress \
      --info=NAME2 --itemize-changes \
      --rsh "ssh -a -k \
        -i '${DEPLOY_KEY}' \
        -o BatchMode=no \
        -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=5" \
      "${_ALL}" \
      "${_ALL}.asc" \
      "${_ALL}.txt" \
      'curl-for-win@silly.haxx.se:.'
  fi

  case "${_HOST}" in
    mac)   rm -f -P "${DEPLOY_KEY}";;
    linux) [ -w "${DEPLOY_KEY}" ] && command -v srm >/dev/null 2>&1 && srm "${DEPLOY_KEY}";;
  esac
  rm -f "${DEPLOY_KEY}"
fi
