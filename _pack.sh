#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

cd "$(dirname "$0")" || exit

_CDO="$(pwd)"

_FN="${_DST}/BUILD-README.txt"
cat << EOF > "${_FN}"
Visit the project page for details about these builds and the list of changes:

   ${_URL}

Please donate to support maintaining these builds:

   PayPal:
      https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPSZQYKXMQJYG

Thank you!
EOF
unix2dos -k "${_FN}"
touch -c -r "$1" "${_FN}"

_FN="${_DST}/BUILD-HOMEPAGE.url"
cat << EOF > "${_FN}"
[InternetShortcut]
URL=${_URL}
EOF
unix2dos -k "${_FN}"
touch -c -r "$1" "${_FN}"

find "${_DST}" -type d -d -exec touch -c -r "$1" '{}' \;

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
