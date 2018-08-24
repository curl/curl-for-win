#!/bin/sh

# Copyright 2014-2018 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

cd "$(dirname "$0")" || exit

# Detect host OS
case "$(uname)" in
  *_NT*)   os='win';;
  Linux*)  os='linux';;
  Darwin*) os='mac';;
  *BSD)    os='bsd';;
esac

export BINTRAY_USER='vszakats'
#[ -n "${BINTRAY_USER}" ] || BINTRAY_USER="${APPVEYOR_ACCOUNT_NAME}"
#[ -n "${BINTRAY_USER}" ] || BINTRAY_USER="$(echo "${TRAVIS_REPO_SLUG}" | sed 's|/.*||')"
#[ -n "${BINTRAY_USER}" ] || BINTRAY_USER="${USER}"

do_upload() {
  arch_ext="$1"

  if [ "${_BRANCH#*master*}" != "${_BRANCH}" ]; then
    _sufpkg=
    _suf=

    if [ ! "${PUBLISH_PROD_FROM}" = "${os}" ]; then
      _suf="-built-on-${os}"
      mv "${_BAS}${arch_ext}" "${_BAS}${_suf}${arch_ext}"
      unset BINTRAY_USER
      unset BINTRAY_APIKEY
    fi
  else
    # Do not sign test packages
    GPG_PASSPHRASE=
    _sufpkg='-test'
    _suf="-test-built-on-${os}"
    mv "${_BAS}${arch_ext}" "${_BAS}${_suf}${arch_ext}"
  fi

  (
    # - Bintray behavior when passphrased private key is provided:
    #   - Repository option: "GPG sign uploaded files using Bintray's public/private key pair."
    #     - passphrase set      -> Success, Bintray signature
    #     - empty/no passphrase -> Warning, Bintray signature
    #   - Repository option: "GPG Sign uploaded files automatically."
    #     - passphrase set      -> Success, Custom signature
    #     - empty/no passphrase -> Warning, No signature

    set +x

    if [ -n "${BINTRAY_USER}" ] && \
       [ -n "${BINTRAY_APIKEY}" ]; then

      echo "Uploading: '${_BAS}${_suf}${arch_ext}' to 'https://api.bintray.com/content/${BINTRAY_USER}/generic/${_NAM}${_sufpkg}/${_VER}/'"

      # TODO: Do this before upload to avoid 403 error for
      # uploads older than 180 days:
      #   https://bintray.com/docs/api/#url_update_version

      curl -fsS -u "${BINTRAY_USER}:${BINTRAY_APIKEY}" \
        -X PUT "https://api.bintray.com/content/${BINTRAY_USER}/generic/${_NAM}${_sufpkg}/${_VER}/${_BAS}${_suf}${arch_ext}?override=1&publish=1" \
        --data-binary "@${_BAS}${_suf}${arch_ext}" \
        -H "X-GPG-PASSPHRASE: ${GPG_PASSPHRASE}"
    fi
  )

  (
    set +x
    if [ -f "${DEPLOY_KEY}" ]; then
      echo "Uploading: '${_BAS}${_suf}${arch_ext}'"
      scp -p -B -o BatchMode=yes -o StrictHostKeyChecking=yes -i "${DEPLOY_KEY}" ${_BAS}${_suf}${arch_ext} curl-for-win@haxx.se:.
    fi
  )

  # <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
  case "${os}" in
    bsd|mac) TZ=UTC stat -f '%N: %z bytes %Sm' -t '%Y-%m-%d %H:%M' "${_BAS}${_suf}${arch_ext}";;
    *)       TZ=UTC stat -c '%n: %s bytes %y' "${_BAS}${_suf}${arch_ext}";;
  esac

  openssl dgst -sha256 "${_BAS}${_suf}${arch_ext}" | tee -a hashes.txt

  if [ "${_BRANCH#*master*}" != "${_BRANCH}" ]; then
  (
    set +x
    out="$(curl -fsS \
      -X POST 'https://www.virustotal.com/vtapi/v2/file/scan' \
      --form-string "apikey=${VIRUSTOTAL_APIKEY}" \
      --form "file=@${_BAS}${_suf}${arch_ext}")"
    echo "${out}"
    echo "VirusTotal URL for '${_BAS}${_suf}${arch_ext}':"
    # echo "${out}" | jq '.permalink'
    echo "${out}" | grep -o 'https://[a-zA-Z0-9./]*'
  )
  fi
}

do_upload '.tar.xz'
do_upload '.zip'
