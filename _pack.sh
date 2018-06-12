#!/bin/sh -x

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

# Map tar to GNU tar, if it exists (e.g. on macOS)
command -v gtar > /dev/null && alias tar=gtar

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

# NOTE: This isn't effective on MSYS2
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
      .tar.xz) tar -c \
        --owner=0 --group=0 --numeric-owner --mode=go=rX,u+rw,a-s --sort=name \
        "${_BAS}" | xz > "${_cdo}/${_BAS}${arch_ext}";;
      .zip)    zip -q -9 -X -r "${_cdo}/${_BAS}${arch_ext}" "${_BAS}";;
      # Requires: p7zip (MSYS2, Homebrew, Linux rpm), p7zip-full (Linux deb)
      .7z)     7z a -bd -r -mx "${_cdo}/${_BAS}${arch_ext}" "${_BAS}" > /dev/null;;
    esac
    touch -c -r "$1" "${_cdo}/${_BAS}${arch_ext}"
  )
}

create_pack "$1" '.tar.xz'
create_pack "$1" '.zip'

rm -f -r "${_DST:?}"
