#!/bin/sh -ex

# Copyright 2015-2018 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

# Requirements (not a comprehensive list at this point):
#   Windows:
#     MSYS2: zip mingw-w64-{i686,x86_64}-{clang,jq,osslsigncode,python3-pip} gpg python3
#   Linux
#     zip binutils-mingw-w64 gcc-mingw-w64 gnupg-curl jq osslsigncode dos2unix realpath wine
#   Mac:
#     brew install xz gnu-tar mingw-w64 jq osslsigncode dos2unix gpg gnu-sed wine

cd "$(dirname "$0")" || exit

LC_ALL=C
LC_MESSAGES=C
LANG=C

export _BRANCH="${APPVEYOR_REPO_BRANCH}${TRAVIS_BRANCH}${CI_COMMIT_REF_NAME}${GIT_BRANCH}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD)"
[ -n "${_BRANCH}" ] || _BRANCH='master'
export _URL=''
command -v git > /dev/null 2>&1 && _URL="$(git ls-remote --get-url | sed 's|.git$||')"
[ -n "${_URL}" ] || _URL="https://github.com/${APPVEYOR_REPO_NAME}${TRAVIS_REPO_SLUG}"

# Detect host OS
export os
case "$(uname)" in
  *_NT*)   os='win';;
  Linux*)  os='linux';;
  Darwin*) os='mac';;
  *BSD)    os='bsd';;
esac

export PUBLISH_PROD_FROM
[ "${APPVEYOR_REPO_PROVIDER}" = 'gitHub' ] && PUBLISH_PROD_FROM='linux'

rm -f ./*-*-mingw*.*
rm -f hashes.txt
rm -f ./build*.txt

export _BLD='build.txt'

. ./_dl.sh || exit 1

# decrypt code signing key
export CODESIGN_KEY=
CODESIGN_KEY="$(realpath '.')/vszakats.p12"
if [ -f "${CODESIGN_KEY}.asc" ]; then
  (
    set +x
    if [ -n "${CODESIGN_GPG_PASS}" ]; then
      install -m 600 /dev/null "${CODESIGN_KEY}"
      gpg --batch --passphrase "${CODESIGN_GPG_PASS}" -d "${CODESIGN_KEY}.asc" >> "${CODESIGN_KEY}"
    fi
  )
fi
[ -f "${CODESIGN_KEY}" ] || unset CODESIGN_KEY

# decrypt deploy key
DEPLOY_KEY="$(realpath '.')/deploy.key"
if [ -f "${DEPLOY_KEY}.asc" ]; then
  (
    set +x
    if [ -n "${DEPLOY_GPG_PASS}" ]; then
      install -m 600 /dev/null "${DEPLOY_KEY}"
      gpg --batch --passphrase "${DEPLOY_GPG_PASS}" -d "${DEPLOY_KEY}.asc" >> "${DEPLOY_KEY}"
    fi
  )
fi

# add deploy target to known hosts
if [ -f "${DEPLOY_KEY}" ]; then
  readonly host_key='haxx.se ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAo2NVLAYjIPAEuGtdG4EZDIEdpOREiBdo/KE51s5bX1zXJOOlxXmyB53CdWVpi1CR/EDQaEbsXE3gWRb3guOnXlzB3A4bzBa4H25BISeTJf4a7nBz5nUY8JYfcOxD5gIySvnJB/O7GxbU5mHLgvpixTuYeyE5T1AwZgDTAoJio0M='
  if [ ! -f "${HOME}/.ssh/known_hosts" ]; then
    mkdir -m 700 "${HOME}/.ssh"
    install -m 600 /dev/null "${HOME}/.ssh/known_hosts"
  fi
  if ! grep "${host_key}" "${HOME}/.ssh/known_hosts" > /dev/null; then
    echo "${host_key}" >> "${HOME}/.ssh/known_hosts"
  fi
fi

case "${os}" in
  mac)
    alias sed=gsed
    ;;
esac

if [ "${CC}" = 'mingw-clang' ]; then
  echo ".clang$("clang${_CCSUFFIX}" --version | grep -o -E ' [0-9]*\.[0-9]*[\.][0-9]*')" >> "${_BLD}"
fi

case "${os}" in
  mac)   ver="$(brew info --json=v1 mingw-w64 | jq -r '.[] | select(.name == "mingw-w64") | .versions.stable')";;
  linux) ver="$(apt-cache show mingw-w64 | grep '^Version:' | cut -c 10-)";;
  *)     ver='';;
esac
[ -n "${ver}" ] && echo ".mingw-w64 ${ver}" >> "${_BLD}"

_ori_path="${PATH}"

build_single_target() {
  _cpu="$1"

  export _TRIPLET=
  export _SYSROOT=
  export _CCPREFIX=
  export _MAKE='make'
  export _WINE=''

  [ "${_cpu}" = '32' ] && _machine='i686'
  [ "${_cpu}" = '64' ] && _machine='x86_64'

  if [ "${os}" = 'win' ]; then
    export PATH="/mingw${_cpu}/bin:${_ori_path}"
    export _MAKE='mingw32-make'

    # Install required component
    # TODO: add `--progress-bar off` when pip 10.0.0 is available
    pip3 --version
    pip3 --disable-pip-version-check install --user pefile
  else
    if [ "${CC}" = 'mingw-clang' ] && [ "${os}" = 'mac' ]; then
      export PATH="/usr/local/opt/llvm/bin:${_ori_path}"
    fi
    _TRIPLET="${_machine}-w64-mingw32"
    # Prefixes don't work with MSYS2/mingw-w64, because `ar`, `nm` and
    # `runlib` are missing from them. They are accessible either _without_
    # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
    _CCPREFIX="${_TRIPLET}-"
    # mingw-w64 sysroots
    if [ "${os}" = 'mac' ]; then
      _SYSROOT="/usr/local/opt/mingw-w64/toolchain-${_machine}"
    else
      _SYSROOT="/usr/${_TRIPLET}"
    fi
    export _WINE='wine'
  fi

  export _CCVER
  if [ "${CC}" = 'mingw-clang' ]; then
    # We don't use old mingw toolchain versions when building with clang, so this is safe:
    _CCVER='99'
  else
    _CCVER="$("${_CCPREFIX}gcc" -dumpversion | sed -e 's/\<[0-9]\>/0&/g' -e 's/\.//g' | cut -c -2)"
  fi

  echo ".gcc-mingw-w64-${_machine} $(${_CCPREFIX}gcc -dumpversion)" >> "${_BLD}"
  echo ".binutils-mingw-w64-${_machine} $(${_CCPREFIX}ar V | grep -o -E '[0-9]+\.[0-9]+[\.][0-9]*')" >> "${_BLD}"

  command -v osslsigncode > /dev/null 2>&1 || unset CODESIGN_KEY

  time ./zlib.sh       "${ZLIB_VER_}" "${_cpu}"
  time ./brotli.sh   "${BROTLI_VER_}" "${_cpu}"
  time ./libidn2.sh "${LIBIDN2_VER_}" "${_cpu}"
  time ./c-ares.sh    "${CARES_VER_}" "${_cpu}"
  time ./nghttp2.sh "${NGHTTP2_VER_}" "${_cpu}"
  time ./openssl.sh "${OPENSSL_VER_}" "${_cpu}"
  time ./libssh2.sh "${LIBSSH2_VER_}" "${_cpu}"
  time ./curl.sh       "${CURL_VER_}" "${_cpu}"
}

if [ -n "$CPU" ]; then
  build_single_target "${CPU}"
else
  build_single_target 64
  build_single_target 32
fi

sort "${_BLD}" > "${_BLD}.sorted"
mv -f "${_BLD}.sorted" "${_BLD}"

ls -l ./*-*-mingw*.*
cat hashes.txt
cat ./build*.txt

# Create an artifact that includes all packages
_ALL="all-mingw${_REV}.zip"
zip -q -0 -X -o "${_ALL}" ./*-*-mingw*.* hashes.txt "${_BLD}"

# Official deploy
if [ "${_BRANCH#*master*}" != "${_BRANCH}" ] && \
   [ "${PUBLISH_PROD_FROM}" = "${os}" ]; then
(
  set +x
  if [ -f "${DEPLOY_KEY}" ]; then
    echo "Uploading: "${_ALL}""
    scp -p -B -i "${DEPLOY_KEY}" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=20 \
      -o ConnectionAttempts=5 \
      "${_ALL}" curl-for-win@haxx.se:
  fi
)
fi
