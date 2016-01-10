#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

cd "$(dirname "$0")" || exit

_CDO="$(pwd)"

_FN="${_DST}/BUILD-README.txt"
cp -f -p 'BUILD-README.txt' "${_FN}"
unix2dos -k "${_FN}"
touch -c "${_FN}" -r "$1"

_FN="${_DST}/BUILD-HOMEPAGE.url"
echo '[InternetShortcut]' > "${_FN}"
echo "URL=${_URL}" >> "${_FN}"
unix2dos -k "${_FN}"
touch -c "${_FN}" -r "$1"

(
   cd "${_DST}/.." || exit
   rm -f "${_CDO}/${_BAS}.7z"
   case "$(uname)" in
      *_NT*) find "${_BAS}" -exec attrib +A -R {} \;
   esac
   # NOTE: add -stl option after updating to 15.12 or upper
   7z a -bd -r -mx "${_CDO}/${_BAS}.7z" "${_BAS}/*" > /dev/null
   touch -c "${_CDO}/${_BAS}.7z" -r "$1"
)

rm -f -r "${_DST:?}"
