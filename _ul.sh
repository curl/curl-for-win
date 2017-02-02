#!/bin/sh

# Copyright 2014-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

cd "$(dirname "$0")" || exit

# Detect host OS
case "$(uname)" in
   *_NT*)   os='win';;
   linux*)  os='linux';;
   Darwin*) os='mac';;
   *BSD)    os='bsd';;
esac

if [ "${_BRANCH#*master*}" != "${_BRANCH}" ] ; then
   _suf=
else
   # Do not sign test packages
   GPG_PASSPHRASE=
   _suf='-test'
   mv "${_BAS}.7z" "${_BAS}${_suf}.7z"
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
   curl -fsS -u "${BINTRAY_USER}:${BINTRAY_APIKEY}" \
      -X PUT "https://api.bintray.com/content/${BINTRAY_USER}/generic/${_NAM}${_suf}/${_VER}/${_BAS}${_suf}.7z?override=1&publish=1" \
      --data-binary "@${_BAS}${_suf}.7z" \
      -H "X-GPG-PASSPHRASE: ${GPG_PASSPHRASE}"
)

# <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
case "${os}" in
   bsd|mac) stat -f '%N: %z bytes %Sm' -t '%Y-%m-%d %H:%M' "${_BAS}${_suf}.7z";;
   *)       stat -c '%n: %s bytes %y' "${_BAS}${_suf}.7z";;
esac

openssl dgst -sha256 "${_BAS}${_suf}.7z" | tee -a hashes.txt

if [ "${_BRANCH#*master*}" != "${_BRANCH}" ] ; then
   (
      set +x
      out="$(curl -fsS \
         -X POST 'https://www.virustotal.com/vtapi/v2/file/scan' \
         --form-string "apikey=${VIRUSTOTAL_APIKEY}" \
         --form "file=@${_BAS}${_suf}.7z")"
      echo "${out}"
      echo "VirusTotal URL for '${_BAS}${_suf}.7z':"
      # echo "${out}" | jq '.permalink'
      echo "${out}" | grep -o 'https://[a-zA-Z0-9./]*'
   )
fi
