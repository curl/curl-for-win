#!/bin/sh -x

# Copyright 2014-2018 Viktor Szakats <https://github.com/vszakats>
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

find "${_DST}" \( -name '*.exe' -or -name '*.dll' \) -exec chmod -x {} +

create_pack() {
  arch_ext="$2"
  (
    cd "${_DST}/.." || exit
    case "${os}" in
      win) find "${_BAS}" -exec attrib +A -R {} \;
    esac
    rm -f "${_cdo}/${_BAS}${arch_ext}"
    case "${arch_ext}" in
      .tar.xz) tar -c "${_BAS}" | xz > "${_cdo}/${_BAS}${arch_ext}";;
      .zip)    zip -q -9 -X -r "${_cdo}/${_BAS}${arch_ext}" "${_BAS}";;
      .7z)     7z a -bd -r -mx "${_cdo}/${_BAS}${arch_ext}" "${_BAS}" > /dev/null;;
    esac
    touch -c -r "$1" "${_cdo}/${_BAS}${arch_ext}"
  )
}

create_pack "$1" '.tar.xz'
create_pack "$1" '.zip'
create_pack "$1" '.7z'  # compatibility with curl download page

rm -f -r "${_DST:?}"
