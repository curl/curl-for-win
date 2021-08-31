#!/bin/sh -ex

# Copyright 2015-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

# Requirements (not a comprehensive list at this point):
#   Linux
#     zip zstd binutils-mingw-w64 gcc-mingw-w64 gnupg-curl jq osslsigncode dos2unix realpath wine
#   Mac:
#     brew install xz zstd gnu-tar mingw-w64 jq osslsigncode dos2unix gpg gnu-sed wine
#   Windows:
#     MSYS2: zip zstd mingw-w64-{i686,x86_64}-{clang,jq,osslsigncode,python3-pip} gpg python3

# TODO:
#   - Enable Control Flow Guard (once FLOSS toolchains support it)
#   - ARM64 builds (once FLOSS toolchains support it)
#   - Switch to libssh from libssh2?
#   - LLVM -mretpoline
#   - GCC -mindirect-branch -mfunction-return -mindirect-branch-register

# Tools:
#                compiler        build
#                --------------- ----------
#   zlib.sh      clang           cmake
#   zlibng.sh    clang           cmake
#   zstd.sh      clang           cmake
#   brotli.sh    clang           cmake
#   libgsasl.sh  clang           autotools
#   libidn2.sh   clang           autotools
#   nghttp2.sh   clang           cmake
#   nghttp3.sh   clang           cmake
#   c-ares.sh    clang           cmake
#   openssl.sh   gcc/clang (v3)  proprietary
#   ngtcp2.sh    gcc             autotools    TODO: move to cmake and clang (couldn't detect openssl, and even configure needs a manual patch)
#   libssh2.sh   clang           make         TODO: move to cmake
#   curl.sh      clang           make         TODO: move to cmake

cd "$(dirname "$0")" || exit

LC_ALL=C
LC_MESSAGES=C
LANG=C
export GREP_OPTIONS=

readonly _LOG='logurl.txt'
if [ -n "${APPVEYOR_ACCOUNT_NAME}" ]; then
  # https://www.appveyor.com/docs/environment-variables/
  _LOGURL="${APPVEYOR_URL}/project/${APPVEYOR_ACCOUNT_NAME}/${APPVEYOR_PROJECT_SLUG}/build/${APPVEYOR_BUILD_VERSION}/job/${APPVEYOR_JOB_ID}"
# _LOGURL="${APPVEYOR_URL}/api/buildjobs/${APPVEYOR_JOB_ID}/log"
elif [ -n "${GITHUB_RUN_ID}" ]; then
  # https://docs.github.com/actions/reference/environment-variables
  _LOGURL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
else
  # https://docs.gitlab.com/ce/ci/variables/index.html
  _LOGURL="${CI_SERVER_URL}/${CI_PROJECT_PATH}/-/jobs/${CI_JOB_ID}/raw"
fi
echo "${_LOGURL}" | tee "${_LOG}"

export _BRANCH="${APPVEYOR_REPO_BRANCH}${CI_COMMIT_REF_NAME}${GITHUB_REF}${GIT_BRANCH}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD)"
[ -n "${_BRANCH}" ] || _BRANCH='main'
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

# For 'configure'-based builds.
# This is more or less guesswork and this warning remains:
#    `configure: WARNING: using cross tools not prefixed with host triplet`
# Even with `_CCPREFIX` provided.
if [ "${_OS}" != 'win' ]; then
  # https://clang.llvm.org/docs/CrossCompilation.html
  export _CROSS_HOST
  case "${_OS}" in
    win)   _CROSS_HOST='x86_64-pc-mingw32';;
    linux) _CROSS_HOST='x86_64-pc-linux';;  # x86_64-pc-linux-gnu
    mac)   _CROSS_HOST='x86_64-apple-darwin';;
    bsd)   _CROSS_HOST='x86_64-pc-bsd';;
  esac
fi

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
SIGN_PKG_KEY='sign-pkg.gpg.asc'
if [ -f "${SIGN_PKG_KEY}" ] && [ "${SIGN_PKG_KEY_ID}" ]; then
(
  set +x
  echo "${SIGN_PKG_GPG_PASS}" | gpg \
    --batch --yes --no-tty --quiet \
    --pinentry-mode loopback --passphrase-fd 0 \
    --decrypt "${SIGN_PKG_KEY}" 2>/dev/null | \
  gpg --batch --quiet --import
)
fi

# decrypt code signing key
export SIGN_CODE_KEY=
SIGN_CODE_KEY="$(realpath '.')/sign-code.p12"
if [ -f "${SIGN_CODE_KEY}.asc" ]; then
(
  set +x
  if [ -n "${SIGN_CODE_GPG_PASS}" ]; then
    install -m 600 /dev/null "${SIGN_CODE_KEY}"
    echo "${SIGN_CODE_GPG_PASS}" | gpg \
      --batch --yes --no-tty --quiet \
      --pinentry-mode loopback --passphrase-fd 0 \
      --decrypt "${SIGN_CODE_KEY}.asc" 2>/dev/null >> "${SIGN_CODE_KEY}"
  fi
)
fi
[ -f "${SIGN_CODE_KEY}" ] || unset SIGN_CODE_KEY

if [ -f "${SIGN_CODE_KEY}" ]; then
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
    echo "${DEPLOY_GPG_PASS}" | gpg \
      --batch --yes --no-tty --quiet \
      --pinentry-mode loopback --passphrase-fd 0 \
      --decrypt "${DEPLOY_KEY}.asc" 2>/dev/null >> "${DEPLOY_KEY}"
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

unset ver
case "${_OS}" in
  mac)
    ver="$(brew info --json=v2 --formula mingw-w64 | jq --raw-output '.formulae[] | select(.name == "mingw-w64") | .versions.stable')";;
  linux)
    [ -n "${ver}" ] || ver="$(dpkg   --status       mingw-w64)"
    [ -n "${ver}" ] || ver="$(rpm    --query        mingw-w64)"
    [ -n "${ver}" ] || ver="$(pacman --query --info mingw-w64)"
    ver="$(printf '%s' "${ver}" | sed -E 's|^(Version ?:) *(.+)$|\2|g')"
    ;;
esac
[ -n "${ver}" ] && echo ".mingw-w64 ${ver}" >> "${_BLD}"

_ori_path="${PATH}"

build_single_target() {
  export _CPU="$1"

  export _TRIPLET=
  export _SYSROOT=
  export _CCPREFIX=
  export _MAKE='make'
  export _WINE=''

  export _OPTM=
  [ "${_CPU}" = 'x86' ] && _OPTM='-m32'
  [ "${_CPU}" = 'x64' ] && _OPTM='-m64'

  [ "${_CPU}" = 'x86' ]   && _machine='i686'
  [ "${_CPU}" = 'x64' ]   && _machine='x86_64'
  [ "${_CPU}" = 'arm64' ] && _machine="${_CPU}"

  export _PKGSUFFIX
  [ "${_CPU}" = 'x86' ] && _PKGSUFFIX="-win32-mingw"
  [ "${_CPU}" = 'x64' ] && _PKGSUFFIX="-win64-mingw"

  if [ "${_OS}" = 'win' ]; then
    export PATH
    [ "${_CPU}" = 'x86' ] && PATH="/mingw32/bin:${_ori_path}"
    [ "${_CPU}" = 'x64' ] && PATH="/mingw64/bin:${_ori_path}"
    export _MAKE='mingw32-make'

    # Install required component
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
      if [ "${_CPU}" = 'x64' ] && \
         [ "$(uname -m)" = 'x86_64' ] && \
         [ "$(sysctl -i -n sysctl.proc_translated)" != '1' ]; then
        _WINE='wine64'
      else
        _WINE='echo'
      fi
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

  echo ".gcc-mingw-w64-${_machine} $("${_CCPREFIX}gcc" -dumpversion)" >> "${_BLD}"
  echo ".binutils-mingw-w64-${_machine} $("${_CCPREFIX}ar" V | grep -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')" >> "${_BLD}"

  command -v "$(dirname "$0")/osslsigncode-local" >/dev/null 2>&1 || unset SIGN_CODE_KEY

  time ./zlib.sh         "${ZLIB_VER_}"
  time ./zlibng.sh     "${ZLIBNG_VER_}"
  time ./zstd.sh         "${ZSTD_VER_}"
  time ./brotli.sh     "${BROTLI_VER_}"
  time ./libgsasl.sh "${LIBGSASL_VER_}"
  time ./libidn2.sh   "${LIBIDN2_VER_}"
  time ./nghttp2.sh   "${NGHTTP2_VER_}"
  time ./nghttp3.sh   "${NGHTTP3_VER_}"
  time ./c-ares.sh      "${CARES_VER_}"
  time ./openssl.sh   "${OPENSSL_VER_}"
  time ./ngtcp2.sh     "${NGTCP2_VER_}"
  time ./libssh2.sh   "${LIBSSH2_VER_}"
  time ./curl.sh         "${CURL_VER_}"
}

# Build binaries
# build_single_target arm64
  build_single_target x64
  build_single_target x86

rm -f "${SIGN_CODE_KEY}"

# Upload/deploy binaries
. ./_ul.sh || exit 1
