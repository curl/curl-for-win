#!/bin/sh

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

cd "$(dirname "$0")" || exit

if [ "${APPVEYOR_REPO_BRANCH}" != "master" ] ; then
   _SUF='-test'
   mv "${_BAS}.7z" "${_BAS}${_SUF}.7z"
else
   _SUF=
fi

(
   set +x
   curl -fsS -u "${BINTRAY_USER}:${BINTRAY_APIKEY}" \
      -X PUT "https://api.bintray.com/content/${BINTRAY_USER}/generic/${_NAM}${_SUF}/${_VER}/${_BAS}${_SUF}.7z?override=1&publish=1" \
      --data-binary "@${_BAS}${_SUF}.7z"
)

# <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
case "$(uname)" in
   *BSD|Darwin) stat -f '%N: %z bytes %Sa' -t '%Y-%m-%d %H:%M' "${_BAS}${_SUF}.7z";;
   *)           stat -c '%n: %s bytes %z' "${_BAS}${_SUF}.7z";;
esac

openssl dgst -sha256 "${_BAS}${_SUF}.7z"
openssl dgst -sha256 "${_BAS}${_SUF}.7z" >> hashes.txt

if [ "${APPVEYOR_REPO_BRANCH}" = "master" ] ; then
   (
      set +x
      curl -fsS \
         -X POST 'https://www.virustotal.com/vtapi/v2/file/scan' \
         --form "apikey=${VIRUSTOTAL_APIKEY}" \
         --form "file=@${_BAS}${_SUF}.7z"
   )
fi
