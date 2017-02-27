#!/bin/sh -ex

# Copyright 2015-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

# Requirements (not a comprehensive list at this point):
#   Windows:
#     MSYS2: p7zip mingw-w64-{i686,x86_64}-{jq,osslsigncode} gpg python
#   Linux
#     p7zip-full binutils-mingw-w64 gcc-mingw-w64 gnupg-curl jq osslsigncode dos2unix realpath wine
#   Mac:
#     brew install p7zip mingw-w64 jq osslsigncode dos2unix gpg
#     brew cask install wine-devel

cd "$(dirname "$0")" || exit

export _BRANCH="${APPVEYOR_REPO_BRANCH}${TRAVIS_BRANCH}${CI_BUILD_REF_NAME}${GIT_BRANCH}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD)"
[ -n "${_BRANCH}" ] || _BRANCH='master'
export _URL=''
which git > /dev/null && _URL="$(git ls-remote --get-url | sed 's|.git$||')"
[ -n "${_URL}" ] || _URL="https://github.com/${APPVEYOR_REPO_NAME}${TRAVIS_REPO_SLUG}"

# Detect host OS
case "$(uname)" in
  *_NT*)   os='win';;
  Linux*)  os='linux';;
  Darwin*) os='mac';;
  *BSD)    os='bsd';;
esac

rm -f ./*.7z
rm -f hashes.txt

. ./_dl.sh || exit 1

# decrypt code signing key
export CODESIGN_KEY=
CODESIGN_KEY="$(realpath '.')/vszakats.p12"
(
  set +x
  if [ -n "${CODESIGN_GPG_PASS}" ]; then
    gpg --batch --passphrase "${CODESIGN_GPG_PASS}" -o "${CODESIGN_KEY}" -d "${CODESIGN_KEY}.asc"
  fi
)
[ -f "${CODESIGN_KEY}" ] || unset CODESIGN_KEY
which osslsigncode > /dev/null || unset CODESIGN_KEY

_ori_path="${PATH}"

for _cpu in '32' '64'; do

  export _CCPREFIX=
  export _MAKE='make'
  export _WINE=''

  if [ "${os}" = 'win' ]; then
    # Use custom mingw compiler package, if installed.
    if [ -d './mingw64/bin' ]; then
      tmp="$(realpath './mingw64/bin')"
    else
      tmp="/mingw${_cpu}/bin"
      if [ "${APPVEYOR}" = 'True' ]; then
        # mingw-w64 comes with its own Python copy. Override that with
        # AppVeyor's external one, which has our extra installed 'pefile'
        # package.
        tmp="/c/Python27-x64:${tmp}"
      fi
    fi
    export PATH="${tmp}:${_ori_path}"
    export _MAKE='mingw32-make'
  else
    # Prefixes don't work with MSYS2/mingw-w64, because `ar`, `nm` and
    # `runlib` are missing from them. They are accessible either _without_
    # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
    [ "${_cpu}" = '32' ] && _CCPREFIX='i686-w64-mingw32-'
    [ "${_cpu}" = '64' ] && _CCPREFIX='x86_64-w64-mingw32-'
    export _WINE='wine'
  fi

  ./zlib.sh         "${ZLIB_VER_}" "${_cpu}"
  ./libidn.sh     "${LIBIDN_VER_}" "${_cpu}"
  ./c-ares.sh      "${CARES_VER_}" "${_cpu}"
  ./nghttp2.sh   "${NGHTTP2_VER_}" "${_cpu}"
  ./libressl.sh "${LIBRESSL_VER_}" "${_cpu}"
  ./openssl.sh   "${OPENSSL_VER_}" "${_cpu}"
  ./librtmp.sh   "${LIBRTMP_VER_}" "${_cpu}"
  ./libssh2.sh   "${LIBSSH2_VER_}" "${_cpu}"
  ./curl.sh         "${CURL_VER_}" "${_cpu}"
done

ls -l ./*-*-mingw*.*
cat hashes.txt

# Move everything into a single artifact
if [ "${_BRANCH#*all*}" != "${_BRANCH}" ]; then
  7z a -bd -r -mx 'all-mingw.7z' ./*-*-mingw*.* > /dev/null
  rm ./*-*-mingw*.*
fi
