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

   # Use custom mingw compiler package, if installed.
   if [ -d './mingw64/bin' ] ; then
      tmp="$(realpath './mingw64/bin')"
   else
      # mingw-w64 comes with its own Python copy. Override that with
      # AppVeyor's external one, which has our extra installed 'pefile'
      # package. MSYS2's own Python is not good either, as its default
      # gcc toolchain would override mingw-w64, if put it front in PATH.
      tmp="/mingw${_CPU}/bin"
      if [ "${APPVEYOR}" = 'True' ] ; then
         tmp="/c/Python27-x64:${tmp}"
      fi
   fi
   export PATH="${tmp}:${_ORI_PATH}"

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
