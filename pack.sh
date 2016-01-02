#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

_CDO="$(pwd)"

(
   cd "${_DST}/.." || exit
   rm -f "${_CDO}/${_BAS}.7z"
   case "$(uname)" in
      *_NT*) find "${_BAS}" -exec attrib +A -R {} \;
   esac
   # NOTE: add -stl option after updating to 15.12 or upper
   7z a -bd -r -mx "${_CDO}/${_BAS}.7z" "${_BAS}/*" > /dev/null
)

rm -f -r "${_DST:?}"
