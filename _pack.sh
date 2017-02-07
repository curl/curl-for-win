#!/bin/sh -x

# Copyright 2014-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

cd "$(dirname "$0")" || exit

# Detect host OS
case "$(uname)" in
   *_NT*)   os='win';;
   Linux*)  os='linux';;
   Darwin*) os='mac';;
   *BSD)    os='bsd';;
esac

_cdo="$(pwd)"

_fn="${_DST}/BUILD-README.txt"
cat << EOF > "${_fn}"
Visit the project page for details about these builds and the list of changes:

   ${_URL}

Please donate to support maintaining these builds:

   PayPal:
      https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2DZM6WAGRJWT6

Thank you!
EOF
unix2dos -k "${_fn}"
touch -c -r "$1" "${_fn}"

_fn="${_DST}/BUILD-HOMEPAGE.url"
cat << EOF > "${_fn}"
[InternetShortcut]
URL=${_URL}
EOF
unix2dos -k "${_fn}"
touch -c -r "$1" "${_fn}"

find "${_DST}" -depth -type d -exec touch -c -r "$1" '{}' \;

(
   cd "${_DST}/.." || exit
   rm -f "${_cdo}/${_BAS}.7z"
   case "${os}" in
      win) find "${_BAS}" -exec attrib +A -R {} \;
   esac
   # NOTE: add -stl option after updating to 15.12 or upper
   7z a -bd -r -mx "${_cdo}/${_BAS}.7z" "${_BAS}/*" > /dev/null
   touch -c "${_cdo}/${_BAS}.7z" -r "$1"
)

rm -f -r "${_DST:?}"
