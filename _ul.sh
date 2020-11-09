#!/bin/sh

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
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
#[ -n "${BINTRAY_USER}" ] || BINTRAY_USER="$(echo "${GITHUB_REPOSITORY}" | sed 's|/.*||')"
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

      # Do this before upload to avoid 403 error for
      # uploads older than 365 days:
      #   https://bintray.com/docs/api/#url_update_version
      # [This loophole/bug was fixed as of 2020-10]

      curl --user-agent curl \
        --fail --silent --show-error \
        --user "${BINTRAY_USER}:${BINTRAY_APIKEY}" \
        --request PUT "https://api.bintray.com/content/${BINTRAY_USER}/generic/${_NAM}${_sufpkg}/${_VER}/${_BAS}${_suf}${arch_ext}?override=1&publish=1" \
        --data-binary "@${_BAS}${_suf}${arch_ext}" \
        --header "X-GPG-PASSPHRASE: ${GPG_PASSPHRASE}"
    fi
  )

  # <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
  case "${os}" in
    bsd|mac) TZ=UTC stat -f '%N: %z bytes %Sm' -t '%Y-%m-%d %H:%M' "${_BAS}${_suf}${arch_ext}";;
    *)       TZ=UTC stat --format '%n: %s bytes %y' "${_BAS}${_suf}${arch_ext}";;
  esac

  openssl dgst -sha256 "${_BAS}${_suf}${arch_ext}" | tee -a hashes.txt
  openssl dgst -sha512 "${_BAS}${_suf}${arch_ext}" | tee -a hashes.txt

  if [ "${_BRANCH#*master*}" != "${_BRANCH}" ]; then
  (
    set +x

    hshl="$(openssl dgst -sha256 "${_BAS}${_suf}${arch_ext}" \
      | sed -n -E 's,.+= ([0-9a-fA-F]{64}),\1,p')"
    # https://developers.virustotal.com/v3.0/reference
    out="$(curl --user-agent curl \
      --fail --silent --show-error \
      --request POST 'https://www.virustotal.com/api/v3/files' \
      --header "x-apikey: ${VIRUSTOTAL_APIKEY}" \
      --form "file=@${_BAS}${_suf}${arch_ext}")"
    # shellcheck disable=SC2181
    if [ "$?" = 0 ]; then
      id="$(echo "${out}" | jq --raw-output '.data.id')"
      out="$(curl --user-agent curl \
        --fail --silent --show-error \
        --request GET "https://www.virustotal.com/api/v3/analyses/${id}" \
        --header "x-apikey: ${VIRUSTOTAL_APIKEY}")"
      # shellcheck disable=SC2181
      if [ "$?" = 0 ]; then
        hshr="$(echo "${out}" | jq --raw-output '.meta.file_info.sha256')"
        if [ "${hshr}" = "${hshl}" ]; then
          echo "VirusTotal URL for '${_BAS}${_suf}${arch_ext}':"
          echo "https://www.virustotal.com/file/${hshr}/analysis/"
        else
          echo "VirusTotal hash mismatch with local hash:"
          echo "Remote: '${hshr}' vs."
          echo " Local: '${hshl}'"
        fi
      else
        echo "Error querying VirusTotal upload: $?"
      fi
    else
      echo "Error uploading to VirusTotal: $?"
    fi
  )
  fi
}

do_upload '.tar.xz'
do_upload '.zip'
