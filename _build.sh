#!/bin/sh -x

# Copyright 2015-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

cd "$(dirname "$0")" || exit

export _BRANCH="${APPVEYOR_REPO_BRANCH}${TRAVIS_BRANCH}${GIT_BRANCH}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git branch --no-color 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/')"
export _URL=''
which git > /dev/null && _URL="$(git ls-remote --get-url | sed 's|\.git||')"
[ -n "${_URL}" ] || _URL="https://github.com/${APPVEYOR_REPO_NAME}${TRAVIS_REPO_SLUG}"

. ./_dl.sh || exit 1

_ORI_PATH="${PATH}"

for _CPU in '32' '64' ; do

   export _CCPREFIX=

   # Use custom mingw compiler package, if installed.
   if [ -d './mingw64/bin' ] ; then
      tmp="$(realpath './mingw64/bin')"
   else
      tmp="/mingw${_CPU}/bin"
      if [ "${APPVEYOR}" = 'True' ] ; then
         # mingw-w64 comes with its own Python copy. Override that with
         # AppVeyor's external one, which has our extra installed 'pefile'
         # package.
         tmp="/c/Python27-x64:${tmp}"
      fi
      [ "${_CPU}" = '32' ] && _CCPREFIX='i686-w64-mingw32-'
      [ "${_CPU}" = '64' ] && _CCPREFIX='x86_64-w64-mingw32-'
   fi
   export PATH="${tmp}:${_ORI_PATH}"

   # Prefixes don't work with MSYS2/mingw-w64, because `ar`, `nm` and
   # `runlib` are missing from them. They are accessible either _without_
   # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
   case "$(uname)" in
      *_NT*) _CCPREFIX=
   esac

   ./libidn.sh     "${LIBIDN_VER_}" "${_CPU}"
   ./c-ares.sh      "${CARES_VER_}" "${_CPU}"
   ./nghttp2.sh   "${NGHTTP2_VER_}" "${_CPU}"
   ./libressl.sh "${LIBRESSL_VER_}" "${_CPU}"
   ./openssl.sh   "${OPENSSL_VER_}" "${_CPU}"
   ./librtmp.sh   "${LIBRTMP_VER_}" "${_CPU}"
   ./libssh2.sh   "${LIBSSH2_VER_}" "${_CPU}"
   ./curl.sh         "${CURL_VER_}" "${_CPU}"
done

ls -l ./*-*-mingw*.*
cat hashes.txt

# Move everything into a single artifact
if [ "${_BRANCH#*all*}" != "${_BRANCH}" ] ; then
   7z a -bd -r -mx 'all-mingw.7z' ./*-*-mingw*.* > /dev/null
   rm ./*-*-mingw*.*
fi
