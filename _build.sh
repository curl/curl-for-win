#!/bin/sh -ex

# Copyright 2015-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

# Requirements (not a comprehensive list at this point):
#   Windows:
#     MSYS2: zip zstd mingw-w64-{i686,x86_64}-{clang,jq,osslsigncode,python3-pip} gpg python3
#   Linux
#     zip zstd binutils-mingw-w64 gcc-mingw-w64 gnupg-curl jq osslsigncode dos2unix realpath wine
#   Mac:
#     brew install xz zstd gnu-tar mingw-w64 jq osslsigncode dos2unix gpg gnu-sed wine

cd "$(dirname "$0")" || exit

LC_ALL=C
LC_MESSAGES=C
LANG=C

readonly _LOG='logurl.txt'
if [ -n "${APPVEYOR_ACCOUNT_NAME}" ]; then
  _LOGURL="https://ci.appveyor.com/project/${APPVEYOR_ACCOUNT_NAME}/${APPVEYOR_PROJECT_SLUG}/build/${APPVEYOR_BUILD_VERSION}/job/${APPVEYOR_JOB_ID}"
# _LOGURL="https://ci.appveyor.com/api/buildjobs/${APPVEYOR_JOB_ID}/log"
elif [ -n "${GITHUB_RUN_ID}" ]; then
  # https://help.github.com/en/actions/configuring-and-managing-workflows/using-environment-variables
  _LOGURL="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
else
  # TODO: https://docs.gitlab.com/ce/ci/variables/README.html
  _LOGURL=''
fi
echo "${_LOGURL}" | tee "${_LOG}"

export _BRANCH="${APPVEYOR_REPO_BRANCH}${CI_COMMIT_REF_NAME}${GITHUB_REF}${GIT_BRANCH}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD)"
[ -n "${_BRANCH}" ] || _BRANCH='master'
export _URL=''
command -v git >/dev/null 2>&1 && _URL="$(git ls-remote --get-url | sed 's|.git$||')"
[ -n "${_URL}" ] || _URL="https://github.com/${APPVEYOR_REPO_NAME}${GITHUB_REPOSITORY}"

# Detect host OS
export _OS
case "$(uname)" in
  *_NT*)   _OS='win';;
  Linux*)  _OS='linux';;
  Darwin*) _OS='mac';;
  *BSD)    _OS='bsd';;
  *)       _OS='unrecognized';;
esac

export PUBLISH_PROD_FROM
if [ "${APPVEYOR_REPO_PROVIDER}" = 'gitHub' ] || \
   [ -n "${GITHUB_RUN_ID}" ]; then
  PUBLISH_PROD_FROM='linux'
fi

export _BLD='build.txt'

rm -f ./*-*-mingw*.*
rm -f hashes.txt
rm -f "${_BLD}"

# Download sources
. ./_dl.sh || exit 1

# Decrypt package signing key
PACKSIGN_KEY='signpack.gpg.asc'
if [ -f "${PACKSIGN_KEY}" ] && [ "${PACKSIGN_KEY_ID}" ]; then
(
  set +x
  gpg --batch --quiet --passphrase "${PACKSIGN_GPG_PASS}" --decrypt "${PACKSIGN_KEY}" | \
  gpg --batch --quiet --import
)
fi

# decrypt code signing key
export CODESIGN_KEY=
CODESIGN_KEY="$(realpath '.')/signcode.p12"
if [ -f "${CODESIGN_KEY}.asc" ]; then
(
  set +x
  if [ -n "${CODESIGN_GPG_PASS}" ]; then
    install -m 600 /dev/null "${CODESIGN_KEY}"
    gpg --batch --passphrase "${CODESIGN_GPG_PASS}" --decrypt "${CODESIGN_KEY}.asc" >> "${CODESIGN_KEY}"
  fi
)
fi
[ -f "${CODESIGN_KEY}" ] || unset CODESIGN_KEY

if [ -f "${CODESIGN_KEY}" ]; then
  # build a patched binary of osslsigncode
  ./osslsigncode.sh
fi

ls -l "$(dirname "$0")/osslsigncode-local"*

# decrypt deploy key
DEPLOY_KEY="$(realpath '.')/deploy.key"
if [ -f "${DEPLOY_KEY}.asc" ]; then
(
  set +x
  if [ -n "${DEPLOY_GPG_PASS}" ]; then
    install -m 600 /dev/null "${DEPLOY_KEY}"
    gpg --batch --passphrase "${DEPLOY_GPG_PASS}" --decrypt "${DEPLOY_KEY}.asc" >> "${DEPLOY_KEY}"
  fi
)
fi

# add deploy target to known hosts
if [ -f "${DEPLOY_KEY}" ]; then
  # ssh-keyscan silly.haxx.se
  readonly host_key='silly.haxx.se ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFVVUP9dpjNl2qbHkDYMDS+cTOfxFytjkC04Oh9RNJBg'
  if [ ! -f "${HOME}/.ssh/known_hosts" ]; then
    mkdir -m 700 "${HOME}/.ssh"
    install -m 600 /dev/null "${HOME}/.ssh/known_hosts"
  fi
  if ! grep -q -a -F "${host_key}" -- "${HOME}/.ssh/known_hosts"; then
    echo "${host_key}" >> "${HOME}/.ssh/known_hosts"
  fi
fi

case "${_OS}" in
  mac) alias sed=gsed;;
esac

if [ "${CC}" = 'mingw-clang' ]; then
  echo ".clang$("clang${_CCSUFFIX}" --version | grep -o -a -E ' [0-9]*\.[0-9]*[\.][0-9]*')" >> "${_BLD}"
fi

case "${_OS}" in
  mac)   ver="$(brew info --json=v1 mingw-w64 | jq --raw-output '.[] | select(.name == "mingw-w64") | .versions.stable')";;
  # FIXME: Linux-distro specific
  linux) ver="$(apt-cache show mingw-w64 | grep -a '^Version:' | cut -c 10-)";;
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

  if [ "${_OS}" = 'win' ]; then
    export PATH="/mingw${_cpu}/bin:${_ori_path}"
    export _MAKE='mingw32-make'

    # Install required component
    # TODO: add `--progress-bar off` when pip 10.0.0 is available
    pip3 --version
    pip3 --disable-pip-version-check --no-cache-dir install --user pefile
  else
    if [ "${CC}" = 'mingw-clang' ] && [ "${_OS}" = 'mac' ]; then
      export PATH="/usr/local/opt/llvm/bin:${_ori_path}"
    fi
    _TRIPLET="${_machine}-w64-mingw32"
    # Prefixes don't work with MSYS2/mingw-w64, because `ar`, `nm` and
    # `runlib` are missing from them. They are accessible either _without_
    # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
    _CCPREFIX="${_TRIPLET}-"
    # mingw-w64 sysroots
    if [ "${_OS}" = 'mac' ]; then
      _SYSROOT="/usr/local/opt/mingw-w64/toolchain-${_machine}"
    else
      _SYSROOT="/usr/${_TRIPLET}"
    fi
    if [ "${_OS}" = 'mac' ]; then
      _WINE='wine64'
    else
      _WINE='wine'
    fi
  fi

  export _CCVER
  if [ "${CC}" = 'mingw-clang' ]; then
    # We don't use old mingw toolchain versions when building with clang, so this is safe:
    _CCVER='99'
  else
    _CCVER="$("${_CCPREFIX}gcc" -dumpversion | sed -e 's/\<[0-9]\>/0&/g' -e 's/\.//g' | cut -c -2)"
  fi

  echo ".gcc-mingw-w64-${_machine} $(${_CCPREFIX}gcc -dumpversion)" >> "${_BLD}"
  echo ".binutils-mingw-w64-${_machine} $(${_CCPREFIX}ar V | grep -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')" >> "${_BLD}"

  command -v "$(dirname "$0")/osslsigncode-local" >/dev/null 2>&1 || unset CODESIGN_KEY

  time ./zlib.sh       "${ZLIB_VER_}" "${_cpu}"
  time ./zstd.sh       "${ZSTD_VER_}" "${_cpu}"
  time ./brotli.sh   "${BROTLI_VER_}" "${_cpu}"
  time ./libidn2.sh "${LIBIDN2_VER_}" "${_cpu}"
  time ./c-ares.sh    "${CARES_VER_}" "${_cpu}"
  time ./nghttp2.sh "${NGHTTP2_VER_}" "${_cpu}"
  time ./nghttp3.sh "${NGHTTP3_VER_}" "${_cpu}"
  time ./openssl.sh "${OPENSSL_VER_}" "${_cpu}"
  time ./ngtcp2.sh   "${NGTCP2_VER_}" "${_cpu}"
  time ./libssh2.sh "${LIBSSH2_VER_}" "${_cpu}"
  time ./curl.sh       "${CURL_VER_}" "${_cpu}"
}

# Build binaries
if [ -n "${CPU}" ]; then
  build_single_target "${CPU}"
else
  build_single_target 64
  build_single_target 32
fi

# Upload/deploy binaries
. ./_ul.sh || exit 1
