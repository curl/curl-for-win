#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Build configuration environment variables:
#
# CW_BLD
#      List of components to build. E.g. 'curl' or 'zlib libssh2 curl' or 'zlib curl-cmake' or 'none'.
#      Optional. Default: (all)
#
# CW_GET
#      List of components to (re-)download. E.g. 'zlib curl' or 'none'.
#      Optional. Default: (all)
#
# CW_LLVM_MINGW_PATH
#      Point to LLVM MinGW installation.
#
# CW_CONFIG
#      Build configuration. Certain keywords select certain configurations. E.g.: 'main-micro'.
#      Optional. Default: 'main' (inherited from the active repo branch name)
#
#      Supported keywords:
#        main       production build
#        test       test build (.map files enabled by default, publishing disabled)
#        dev        development build (use source snapshots instead of stable releases)
#        noh3       build without HTTP/3 (QUIC) support (select stock OpenSSL instead of quictls)
#        nobrotli   build without brotli
#        nozstd     build without zstd
#        noftp      build without FTP/FTPS support
#        boringssl  build with BoringSSL
#        libressl   build with LibreSSL
#        schannel   build with Schannel
#        mbedtls    build with mbedTLS
#        wolfssl    build with wolfSSL (caveats!)
#        wolfssh    build with wolfSSH (requires wolfSSL)
#        libssh     build with libssh
#        big        build with more features, see README.md
#        mini       build with less features, see README.md
#        micro      build with less features, see README.md
#        nano       build with less features, see README.md
#        pico       build with less features, see README.md
#        a64        build ARM64 target only
#        x64        build x64 target only
#        x86        build x86 target only
#        msvcrt     build against msvcrt instead of UCRT
#        gcc        build with GCC (use llvm if not specified)
#        unicode    build curl in UNICODE mode [EXPERIMENTAL]
#        werror     turn compiler warnings into errors
#        debug      debug build
#        mac        build macOS target (requires macOS host)
#        linux      build Linux target (requires Linux host)
#        musl       build Linux target with musl CRT (default: gnu)
#
# CW_JOBS
#      Number of parallel make jobs. Default: 2
#
# CW_CCSUFFIX
#      llvm/clang suffix. E.g. '-8' for clang-8.
#      Optional. Default: (empty)
#
# CW_REVISION
#      Override the stable build revision number.
#
# SIGN_CODE_GPG_PASS, SIGN_CODE_KEY_PASS: for code signing
# SIGN_PKG_KEY_ID, SIGN_PKG_GPG_PASS, SIGN_PKG_KEY_PASS: for package signing
# DEPLOY_GPG_PASS, DEPLOY_KEY_PASS: for publishing results
#      Secrets used for the above operations.
#      Optional. Skipping any operation missing a secret.

# TODO:
#   - Change default TLS to BoringSSL (with OPENSSL_SMALL?) or LibreSSL?
#   - Linux: use musl.
#   - Rename _BRANCH to CW_CONFIG internally.
#   - Replace .zip with .tar.gz for all-packages artifact (in _ul.sh)?
#   - Drop x86 builds.
#       https://data.firefox.com/dashboard/hardware
#       https://gs.statcounter.com/windows-version-market-share
#     A hidden aspect of x86: The Chocolatey package manager installs x86
#     binaries on ARM systems to run them in emulated mode. Windows as of ~2021
#     got the ability to run x64 in emulated mode, but tooling support is
#     missing, just like support for native ARM binaries:
#       https://github.com/chocolatey/choco/issues/1803
#       https://github.com/chocolatey/choco/issues/2172
#     winget and scoop both support native ARM64.

# Resources:
#   - https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html
#   - https://github.com/mstorsjo/llvm-mingw
#   - https://github.com/llvm/llvm-project
#   - https://salsa.debian.org/pkg-llvm-team
#   - https://git.code.sf.net/p/mingw-w64/mingw-w64
#     https://github.com/mirror/mingw-w64
#   - https://sourceware.org/git/binutils-gdb.git
#   - https://github.com/netwide-assembler/nasm

# Build times (2023-07-29):
#   - gnumake:                   33 min 18 sec   1998s   100%
#   - cmake with dual patch:     39 min 12 sec   2352s   118%   100%
#   - autotools:                 41 min 40 sec   2500s   125%   106%

# Supported build tools:
#
#   zlib             cmake
#   zlibng           cmake
#   zstd             cmake
#   brotli           cmake
#   cares            cmake
#   libunistring     autotools
#   libiconv         autotools
#   libidn2          autotools
#   libpsl           autotools
#   gsasl            autotools
#   nghttp2          cmake
#   nghttp3          cmake
#   ngtcp2           cmake
#   wolfssl          autotools
#   mbedtls          cmake
#   openssl/quictls  proprietary
#   boringssl        cmake
#   libressl         autotools, cmake
#   wolfssh          autotools
#   libssh           cmake
#   libssh2          autotools, gnumake [windows-only], cmake
#   curl             gnumake [windows-only], cmake [non-windows default], autotools

# Linux target notes:
# - Debian packages required:
#   - cmake
#   - musl musl-dev musl-tools (for -musl builds)
#
# macOS target notes:
# - Homebrew packages:
#   - llvm (for default builds. Not required for -gcc builds.)

cd "$(dirname "$0")"

export LC_ALL=C
export LC_MESSAGES=C
export LANG=C

export GREP_OPTIONS=
export ZIPOPT=
export ZIP=

unamem="$(uname -m)"

readonly _LOG='logurl.txt'
readonly _SELF='curl-for-win'
if [ -n "${APPVEYOR_ACCOUNT_NAME:-}" ]; then
  # https://www.appveyor.com/docs/environment-variables/
  _SLUG="${APPVEYOR_REPO_NAME}"
  _LOGURL="${APPVEYOR_URL}/project/${APPVEYOR_ACCOUNT_NAME}/${APPVEYOR_PROJECT_SLUG}/build/${APPVEYOR_BUILD_VERSION}/job/${APPVEYOR_JOB_ID}?fullLog=true"
# _LOGURL="${APPVEYOR_URL}/api/buildjobs/${APPVEYOR_JOB_ID}/log"
  _COMMIT="${APPVEYOR_REPO_COMMIT}"
  _COMMIT_SHORT="$(printf '%.8s' "${_COMMIT}")"
elif [ -n "${GITHUB_RUN_ID:-}" ]; then
  # https://docs.github.com/actions/learn-github-actions/environment-variables
  _SLUG="${GITHUB_REPOSITORY}"
  _LOGURL="${GITHUB_SERVER_URL}/${_SLUG}/actions/runs/${GITHUB_RUN_ID}"
  _COMMIT="${GITHUB_SHA}"
  _COMMIT_SHORT="$(printf '%.8s' "${_COMMIT}")"
elif [ -n "${CI_JOB_ID:-}" ]; then
  # https://docs.gitlab.com/ce/ci/variables/index.html
  _SLUG="${CI_PROJECT_PATH}"
  _LOGURL="${CI_SERVER_URL}/${_SLUG}/-/jobs/${CI_JOB_ID}/raw"
  _COMMIT="${CI_COMMIT_SHA}"
  _COMMIT_SHORT="$(printf '%.8s' "${_COMMIT}")"
else
  _SLUG="curl/${_SELF}"
  _LOGURL=''
  _COMMIT="$(git rev-parse --verify HEAD || true)"
  _COMMIT_SHORT="$(git rev-parse --short=8 HEAD || true)"
fi
echo "${_LOGURL}" | tee "${_LOG}"

export _BRANCH
if [ -n "${CW_CONFIG:-}" ]; then
  _BRANCH="${CW_CONFIG}"
else
  _BRANCH="${APPVEYOR_REPO_BRANCH:-}${CI_COMMIT_REF_NAME:-}${GITHUB_REF_NAME:-}"
fi
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD || true)"
[ -n "${_BRANCH}" ] || _BRANCH='main'
if command -v git >/dev/null 2>&1; then
  # Broken on AppVeyor CI since around 2023-02:
  #   fatal: No remote configured to list refs from.
  _URL_BASE="$(git ls-remote --get-url | sed 's/\.git$//' || true)"
fi
if [ -z "${_URL_BASE}" ]; then
  _URL_BASE="https://github.com/${_SLUG}"
fi
if [ -n "${_COMMIT}" ]; then
# _URL_FULL="${_URL_BASE}/tree/${_COMMIT}"
  _TAR="${_URL_BASE}/archive/${_COMMIT}.tar.gz"
else
# _URL_FULL="${_URL_BASE}"
  _TAR="${_URL_BASE}/archive/refs/heads/${_BRANCH}.tar.gz"
fi

# Detect host OS
export _HOSTOS
case "$(uname)" in
  *_NT*)   _HOSTOS='win';;
  Linux*)  _HOSTOS='linux';;
  Darwin*) _HOSTOS='mac';;
  *BSD)    _HOSTOS='bsd';;
  *)       _HOSTOS='unrecognized';;
esac

export _OS='win'
[ ! "${_BRANCH#*mac*}" = "${_BRANCH}" ] && _OS='mac'
[ ! "${_BRANCH#*linux*}" = "${_BRANCH}" ] && _OS='linux'

export _CACERT='cacert.pem'

[ -n "${CW_CCSUFFIX:-}" ] || CW_CCSUFFIX=''

export _CC='llvm'
[ ! "${_BRANCH#*gcc*}" = "${_BRANCH}" ] && _CC='gcc'

export _CRT
if [ "${_OS}" = 'win' ]; then
  _CRT='ucrt'
  [ ! "${_BRANCH#*msvcrt*}" = "${_BRANCH}" ] && _CRT='msvcrt'
elif [ "${_OS}" = 'linux' ]; then
  # TODO: make musl the default (once all issues are cleared)
  _CRT='gnu'
  [ ! "${_BRANCH#*musl*}" = "${_BRANCH}" ] && _CRT='musl'
else
  # macOS: /usr/lib/libSystem.B.dylib
  _CRT='sys'
fi

export DYN_DIR
export DYN_EXT
export BIN_EXT
if [ "${_OS}" = 'win' ]; then
  DYN_DIR='bin'
  DYN_EXT='.dll'
  BIN_EXT='.exe'
elif [ "${_OS}" = 'mac' ]; then
  DYN_DIR='lib'
  DYN_EXT='.dylib'
  BIN_EXT=''
elif [ "${_OS}" = 'linux' ]; then
  DYN_DIR='lib'
  DYN_EXT='.so'
  BIN_EXT=''
fi

if [ -z "${CW_MAP:-}" ]; then
  export CW_MAP='0'
  [ "${_BRANCH#*main*}" = "${_BRANCH}" ] && CW_MAP='1'
fi

export _JOBS=2
[ -n "${CW_JOBS:-}" ] && _JOBS="${CW_JOBS}"

my_time='time'
[ -n "${CW_NOTIME:-}" ] && my_time=

# Form suffix for alternate builds
export _FLAV=''
if [ "${_BRANCH#*pico*}" != "${_BRANCH}" ]; then
  _FLAV='-pico'
elif [ "${_BRANCH#*nano*}" != "${_BRANCH}" ]; then
  _FLAV='-nano'
elif [ "${_BRANCH#*micro*}" != "${_BRANCH}" ]; then
  _FLAV='-micro'
elif [ "${_BRANCH#*mini*}" != "${_BRANCH}" ]; then
  _FLAV='-mini'
elif [ "${_BRANCH#*noh3*}" != "${_BRANCH}" ]; then
  _FLAV='-noh3'
elif [ "${_BRANCH#*big*}" != "${_BRANCH}" ]; then
  _FLAV='-big'
fi

# For 'configure'-based builds.
# This is more or less guesswork and this warning remains:
#    `configure: WARNING: using cross tools not prefixed with host triplet`
# Even with `_CCPREFIX` provided.
# https://clang.llvm.org/docs/CrossCompilation.html
case "${_HOSTOS}" in
  win)   _BUILD_HOST="${unamem}-pc-mingw32";;
  linux) _BUILD_HOST="${unamem}-pc-linux";;
  bsd)   _BUILD_HOST="${unamem}-pc-bsd";;
  mac)   _BUILD_HOST="${unamem}-apple-darwin";;
  *)     _BUILD_HOST="${unamem}-pc-$(uname -s | tr '[:upper:]' '[:lower:]')";;  # lazy guess
esac

export _PKGOS
if [ "${_OS}" = 'win' ]; then
  _PKGOS='mingw'
elif [ "${_OS}" = 'mac' ]; then
  _PKGOS='macos'
else
  _PKGOS="${_OS}"
fi

export PUBLISH_PROD_FROM
if [ "${APPVEYOR_REPO_PROVIDER:-}" = 'gitHub' ] || \
   [ -n "${GITHUB_RUN_ID:-}" ]; then
  PUBLISH_PROD_FROM='linux'
else
  PUBLISH_PROD_FROM=''
fi

export _BLD='build.txt'
export _URLS='urls.txt'

rm -f ./*-*-"${_PKGOS}"*.*
rm -f hashes.txt "${_BLD}" "${_URLS}"

touch hashes.txt "${_BLD}" "${_URLS}"

. ./_versions.sh

# Revision suffix used in package filenames
export _REVSUFFIX="${_REV}"; [ -z "${_REVSUFFIX}" ] || _REVSUFFIX="_${_REVSUFFIX}"

# Download sources
. ./_dl.sh

# Install required component
if [ "${_OS}" = 'win' ] && [ "${_HOSTOS}" = 'mac' ]; then
  if [ ! -d .venv ]; then
    python3 -m venv .venv
    PIP_PROGRESS_BAR=off .venv/bin/python3 -m pip --disable-pip-version-check --no-cache-dir --require-virtualenv install pefile
  fi
  export PATH; PATH="$(realpath \
    "$(dirname "${0}")"/.venv/bin):${PATH}"
fi

# Find and setup llvm-mingw downloaded above.
if [ "${_OS}" = 'win' ] && \
   [ -z "${CW_LLVM_MINGW_PATH:-}" ] && \
   [ -d 'llvm-mingw' ]; then
  export CW_LLVM_MINGW_PATH; CW_LLVM_MINGW_PATH="$(pwd)/llvm-mingw"
  export CW_LLVM_MINGW_VER_; CW_LLVM_MINGW_VER_="$(cat 'llvm-mingw/version.txt')"
  echo "! Using llvm-mingw: '${CW_LLVM_MINGW_PATH}' (${CW_LLVM_MINGW_VER_})"
fi

# Decrypt package signing key
SIGN_PKG_KEY='sign-pkg.gpg.asc'
if [ -s "${SIGN_PKG_KEY}" ] && \
   [ -n "${SIGN_PKG_KEY_ID:-}" ] && \
   [ -n "${SIGN_PKG_GPG_PASS:+1}" ]; then
  gpg --batch --yes --no-tty --quiet \
    --pinentry-mode loopback --passphrase-fd 0 \
    --decrypt "${SIGN_PKG_KEY}" 2>/dev/null <<EOF | \
  gpg --batch --quiet --import
${SIGN_PKG_GPG_PASS}
EOF
fi

# decrypt code signing key
export SIGN_CODE_KEY; SIGN_CODE_KEY="$(realpath '.')/sign-code.p12"
if [ -s "${SIGN_CODE_KEY}.asc" ] && \
   [ -n "${SIGN_CODE_GPG_PASS:+1}" ]; then
  install -m 600 /dev/null "${SIGN_CODE_KEY}"
  gpg --batch --yes --no-tty --quiet \
    --pinentry-mode loopback --passphrase-fd 0 \
    --decrypt "${SIGN_CODE_KEY}.asc" 2>/dev/null >> "${SIGN_CODE_KEY}" <<EOF || true
${SIGN_CODE_GPG_PASS}
EOF
fi

if [ "${_OS}" = 'win' ] && \
   [ -s "${SIGN_CODE_KEY}" ]; then
  osslsigncode --version  # We need 2.2 or newer
fi

_ori_path="${PATH}"

bld() {
  bldtools='(cmake|autotools|gnumake)'
  pkg="$1"
  if [ -z "${CW_BLD:-}" ] || echo " ${CW_BLD} " | grep -q -E -- " ${pkg}(-${bldtools})? "; then
    shift

    export _BLDDIR="${_BLDDIR_BASE}"

    pkgori="${pkg}"
    [ -n "${2:-}" ] && pkg="$2"
    # allow selecting an alternate build tool
    withbuildtool="$(echo "${CW_BLD:-}" | \
      grep -a -o -E -- "${pkg}-${bldtools}" || true)"
    if [ -n "${withbuildtool}" ] && [ -f "${withbuildtool}.sh" ]; then
      pkg="${withbuildtool}"

      bldtool="$(echo "${pkg}" | \
        grep -a -o -E -- "-${bldtools}")"
      _BLDDIR="${_BLDDIR}${bldtool}-${_CC}-${_CPU}"
    fi

    ${my_time} "./${pkg}.sh" "$1" "${pkgori}"

    if [ "${CW_DEV_MOVEAWAY:-}" = '1' ] && [ "${pkg}" != "${pkgori}" ]; then
      mv -n "${pkgori}" "${pkg}"
    fi
  fi
}

build_single_target() {
  export _CPU="$1"

  # Select and advertise a single copy of components having multiple
  # implementations.
  export _ZLIB=''
  if   [ -d zlibng ]; then
    _ZLIB='zlibng'
  elif [ -d zlib ]; then
    _ZLIB='zlib'
  fi
  export _OPENSSL=''
  if   [ -d libressl ]; then
    _OPENSSL='libressl'
  elif [ -d boringssl ]; then
    _OPENSSL='boringssl'
  elif [ -d quictls ]; then
    _OPENSSL='quictls'
  elif [ -d openssl ]; then
    _OPENSSL='openssl'
  fi

  use_llvm_mingw=0
  versuffix_llvm_mingw=''
  versuffix_non_llvm_mingw=''
  if [ "${_OS}" = 'win' ]; then
    if [ "${CW_LLVM_MINGW_ONLY:-}" = '1' ]; then
      use_llvm_mingw=1
    # llvm-mingw is required for x64 (to avoid pthread link bug with BoringSSL),
    # but for consistency, use it for all targets when building with BoringSSL.
    elif [ "${_OPENSSL}" = 'boringssl' ] && [ "${_CRT}" = 'ucrt' ]; then
      use_llvm_mingw=1
    elif [ "${_CPU}" = 'a64' ]; then
      use_llvm_mingw=1
      versuffix_llvm_mingw=' (ARM64)'
    fi
  fi

  # Toolchain
  export _TOOLCHAIN=''
  if [ "${_OS}" = 'win' ]; then
    if [ "${use_llvm_mingw}" = '1' ]; then
      if [ "${_CC}" != 'llvm' ] || \
         [ "${_CRT}" != 'ucrt' ] || \
         [ -z "${CW_LLVM_MINGW_PATH:-}" ]; then
        echo "! WARNING: '${_BRANCH}/${_CPU}' builds require llvm/clang, UCRT and CW_LLVM_MINGW_PATH. Skipping."
        return
      fi
      _TOOLCHAIN='llvm-mingw'
    else
      _TOOLCHAIN='mingw-w64'
    fi
  elif [ "${_OS}" = 'mac' ]; then
    if [ "${_CC}" = 'gcc' ] && \
       "${_CC}" --version | grep -q -a -E '(Apple clang|Apple LLVM|based on LLVM)'; then
      _TOOLCHAIN='llvm-apple'  # Apple clang
    fi
  fi

  export _TRIPLET=''
  _SYSROOT=''

  _CCPREFIX=
  _CCSUFFIX=
  export _MAKE='make'
  export _WINE=''

  if [ ! "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
    _CCSUFFIX="${CW_CCSUFFIX}"
  fi

  # GCC-specific machine selection option
  [ "${_CPU}" = 'x86' ] && _OPTM='-m32'
  [ "${_CPU}" = 'x64' ] && _OPTM='-m64'
  [ "${_CPU}" = 'a64' ] && _OPTM='-marm64pe'

  [ "${_CPU}" = 'x86' ] && _machine='i686'
  [ "${_CPU}" = 'x64' ] && _machine='x86_64'
  [ "${_CPU}" = 'a64' ] && _machine='aarch64'

  export _CURL_DLL_SUFFIX=''
  export _CURL_DLL_SUFFIX_NODASH=''
  if [ "${_OS}" = 'win' ]; then
    [ "${_CPU}" = 'x64' ] && _CURL_DLL_SUFFIX_NODASH="${_CPU}"
    [ "${_CPU}" = 'a64' ] && _CURL_DLL_SUFFIX_NODASH='arm64'
    [ -n "${_CURL_DLL_SUFFIX_NODASH}" ] && _CURL_DLL_SUFFIX="-${_CURL_DLL_SUFFIX_NODASH}"
  fi

  if [ "${_OS}" = 'win' ]; then
    [ "${_CPU}" = 'x86' ] && pkgcpu='win32'
    [ "${_CPU}" = 'x64' ] && pkgcpu='win64'
    [ "${_CPU}" = 'a64' ] && pkgcpu='win64a'
  else
    # TODO: add support for macOS universal (multi-CPU) builds?
    pkgcpu="${_machine}"
  fi
  export _PKGSUFFIX="-${pkgcpu}-${_PKGOS}"

  # Reset for each target
  PATH="${_ori_path}"

  if [ "${_HOSTOS}" = 'mac' ]; then
    if [ -d '/opt/homebrew' ]; then
      brew_root='/opt/homebrew'
    else
      brew_root='/usr/local'
    fi

    _MAC_LLVM_PATH="${brew_root}/opt/llvm/bin"
  fi

  if [ "${_OS}" = 'win' ]; then
    if [ "${_HOSTOS}" = 'win' ]; then
      export PATH
      if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
        PATH="${CW_LLVM_MINGW_PATH}/bin:${_ori_path}"
      else
        [ "${_CPU}" = 'x86' ] && _MSYSROOT='/mingw32'
        [ "${_CPU}" = 'x64' ] && _MSYSROOT='/mingw64'
        [ "${_CPU}" = 'a64' ] && _MSYSROOT='/clangarm64'

        [ -n "${_MSYSROOT}" ] && PATH="${_MSYSROOT}/bin:${_ori_path}"
      fi
      _MAKE='mingw32-make'
    else
      if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
        export PATH="${CW_LLVM_MINGW_PATH}/bin:${_ori_path}"
      elif [ "${_CC}" = 'llvm' ] && [ "${_HOSTOS}" = 'mac' ]; then
        export PATH="${_MAC_LLVM_PATH}:${_ori_path}"
      fi
      _TRIPLET="${_machine}-w64-mingw32"
      # Prefixes do not work with MSYS2/mingw-w64, because `ar`, `nm` and
      # `ranlib` are missing from them. They are accessible either _without_
      # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
      _CCPREFIX="${_TRIPLET}-"
      # mingw-w64 sysroots
      if [ "${_TOOLCHAIN}" != 'llvm-mingw' ]; then
        if [ "${_HOSTOS}" = 'mac' ]; then
          _SYSROOT="${brew_root}/opt/mingw-w64/toolchain-${_machine}"
        elif [ "${_HOSTOS}" = 'linux' ]; then
          _SYSROOT="/usr/${_TRIPLET}"
        fi
      fi

      _WINE='echo'
      if [ "${_HOSTOS}" = 'linux' ] || \
         [ "${_HOSTOS}" = 'bsd' ]; then
        # Run x64 targets on same CPU:
        if [ "${_CPU}" = 'x64' ] && \
           [ "${unamem}" = 'x86_64' ]; then
          if command -v wine64 >/dev/null 2>&1; then
            _WINE='wine64'
          elif command -v wine >/dev/null 2>&1; then
            _WINE='wine'
          fi
        fi
      elif [ "${_HOSTOS}" = 'mac' ]; then
        # Run x64 targets on Intel and ARM (requires Wine 6.0.1):
        if [ "${_CPU}" = 'x64' ] && \
           command -v wine64 >/dev/null 2>&1; then
          _WINE='wine64'
        fi
      elif [ "${_HOSTOS}" = 'win' ]; then
        # Skip ARM64 target on 64-bit Intel, run all targets on ARM64:
        if [ "${unamem}" = 'x86_64' ] && \
           [ "${_CPU}" != 'a64' ]; then
          _WINE=
        elif [ "${unamem}" = 'aarch64' ]; then
          _WINE=
        fi
      fi
    fi
  else
    if [ "${_CC}" = 'llvm' ] && [ "${_HOSTOS}" = 'mac' ]; then
      export PATH="${_MAC_LLVM_PATH}:${_ori_path}"
    fi
    # TODO: add support for linux and mac cross-builds
    _TRIPLET="${_BUILD_HOST}"

    if [ "${_OS}" = 'linux' ]; then
      # Include CRT type in Linux triplets, to make it visible in
      # the curl version banner.
      _TRIPLET="${_TRIPLET}-${_CRT}"
    fi
  fi

  if [ "${_CC}" = 'llvm' ]; then
    ccver="$("clang${_CCSUFFIX}" -dumpversion)"
  else
    if [ "${_CRT}" = 'musl' ]; then
      _CCPREFIX='musl-'
    fi

    ccver="$("${_CCPREFIX}gcc" -dumpversion)"

    if [ "${_CRT}" = 'ucrt' ]; then
      # Create specs files that overrides msvcrt with ucrt. We need this
      # for gcc when building against UCRT.
      #   https://stackoverflow.com/questions/57528555/how-do-i-build-against-the-ucrt-with-mingw-w64
      _GCCSPECS="$(realpath gcc-specs-ucrt)"
      "${_CCPREFIX}gcc" -dumpspecs | sed 's/-lmsvcrt/-lucrt/g' > "${_GCCSPECS}"
    fi
  fi

  export _CCVER
  _CCVER="$(printf '%02d' \
    "$(printf '%s' "${ccver}" | grep -a -o -E '^[0-9]+')")"

  # Setup common toolchain configuration options

  export _TOP; _TOP="$(pwd)"  # Must be an absolute path
  _BLDDIR_BASE='bld'
  export _PKGDIR="${_CPU}-${_CRT}"
  _PREFIX='/usr'
  export _PP="${_PKGDIR}${_PREFIX}"
  export _CC_GLOBAL=''
  export _CFLAGS_GLOBAL=''
  export _CFLAGS_GLOBAL_CMAKE=''
  export _CPPFLAGS_GLOBAL=''
  export _CXXFLAGS_GLOBAL=''
  export _RCFLAGS_GLOBAL=''
  export _LDFLAGS_GLOBAL=''
  export _LDFLAGS_GLOBAL_AUTOTOOLS=''
  export _LDFLAGS_BIN_GLOBAL=''
  export _LDFLAGS_CXX_GLOBAL=''
  export _LIBS_GLOBAL=''
  export _CONFIGURE_GLOBAL=''
  export _CMAKE_GLOBAL='-DCMAKE_BUILD_TYPE=Release'
  export _CMAKE_CXX_GLOBAL=''

  if [ "${_OS}" = 'win' ]; then
    _CMAKE_GLOBAL="-DCMAKE_SYSTEM_NAME=Windows ${_CMAKE_GLOBAL}"
  elif [ "${_OS}" = 'linux' ]; then
    # Override defaults such as: 'lib/aarch64-linux-gnu'
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_INSTALL_LIBDIR=lib"
  fi

  # Suppress CMake warnings meant for upstream developers
  _CMAKE_GLOBAL="-Wno-dev ${_CMAKE_GLOBAL}"

  # for CMake and openssl
  unset CC

  if [ "${_OS}" = 'win' ]; then
    [ "${_CPU}" = 'x86' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=pe-i386"
    [ "${_CPU}" = 'x64' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=pe-x86-64"
    [ "${_CPU}" = 'a64' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=${_TRIPLET}"  # llvm-windres supports triplets here. https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-rc/llvm-rc.cpp
  fi

  if [ "${_HOSTOS}" = 'win' ] && [ "${_OS}" = 'win' ]; then
    # '-G MSYS Makefiles' command-line option is problematic due to spaces
    # and unwanted escaping/splitting. Pass it via envvar instead.
    export CMAKE_GENERATOR='MSYS Makefiles'
    # Without this, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  fi

  _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_INSTALL_MESSAGE=NEVER"
  _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_INSTALL_PREFIX=${_PREFIX}"

  if [ "${_CRT}" = 'ucrt' ]; then
    _CPPFLAGS_GLOBAL="${_CPPFLAGS_GLOBAL} -D_UCRT"
    _LIBS_GLOBAL="${_LIBS_GLOBAL} -lucrt"
    if [ "${_CC}" = 'gcc' ]; then
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -specs=${_GCCSPECS}"
    fi
  fi

  _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --build=${_BUILD_HOST} --host=${_TRIPLET}"
  [ "${_CPU}" = 'x86' ] && _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -fno-asynchronous-unwind-tables"

  export _LD
  if [ "${_CRT}" = 'musl' ]; then
    _BINUTILS_PREFIX=''
  else
    _BINUTILS_PREFIX="${_CCPREFIX}"
  fi
  _BINUTILS_SUFFIX=''
  if [ "${_CC}" = 'llvm' ]; then
    _CC_GLOBAL="clang${_CCSUFFIX} --target=${_TRIPLET}"
    _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --target=${_TRIPLET}"
    if [ -n "${_SYSROOT}" ]; then
      _CC_GLOBAL="${_CC_GLOBAL} --sysroot=${_SYSROOT}"
      _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --with-sysroot=${_SYSROOT}"
    fi
    if [ "${_HOSTOS}" = 'linux' ] && [ "${_OS}" = 'win' ]; then
      # We used to pass this via CFLAGS for CMake to make it detect llvm/clang,
      # so we need to pass this via CMAKE_C_FLAGS, though meant for the linker.
      if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
        _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -L${CW_LLVM_MINGW_PATH}/${_TRIPLET}/lib"
      else
        # https://packages.debian.org/testing/amd64/gcc-mingw-w64-x86-64-posix/filelist
        # https://packages.debian.org/testing/amd64/gcc-mingw-w64-x86-64-win32/filelist
        # /usr/lib/gcc/x86_64-w64-mingw32/10-posix/
        # /usr/lib/gcc/x86_64-w64-mingw32/10-win32/
        # /usr/lib/gcc/x86_64-w64-mingw32/12/
        tmp="$(find "/usr/lib/gcc/${_TRIPLET}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
        if [ -z "${tmp}" ]; then
          >&2 echo '! Error: Failed to detect mingw-w64 dev env root.'
          exit 1
        fi
        _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -L${tmp}"
        _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} -I${tmp}/include/c++"
        _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} -I${tmp}/include/c++/${_TRIPLET}"
        _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} -I${tmp}/include/c++/backward"
      fi
    fi

    if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
      # Requires llvm v16 and mingw-w64 v11 built with `--enable-cfguard`.
      # As of 2023-08, only llvm-mingw satisfies this.
      #
      # Refs:
      #   https://github.com/mstorsjo/llvm-mingw/issues/301
      #   https://gist.github.com/alvinhochun/a65e4177e2b34d551d7ecb02b55a4b0a
      #   https://github.com/mstorsjo/llvm-mingw/compare/master...alvinhochun:llvm-mingw:alvin/cfguard.diff
      #   https://github.com/mingw-w64/mingw-w64/compare/master...alvinhochun:mingw-w64:alvin/cfguard.diff
      #
      # The build is successful with standard distro llvm 16 + mingw-w64 11,
      # but executables fail to run. The linker shows this warning:
      #   ld.lld: warning: Control Flow Guard is enabled but '_load_config_used' is missing
      # Omitting linker option `-mguard=cf` makes the warning disappear, but
      # the executables fail to run anyway. It means that cfguard needs
      # llvm-mingw with all objects compiled with cfguard, and cfguard enabled
      # at link time to end up with a runnable exe.
      _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -mguard=cf"
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -mguard=cf"
    fi

    if [ -n "${_SYSROOT}" ]; then
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_SYSROOT=${_SYSROOT}"
    fi
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER=clang${_CCSUFFIX}"
    _CMAKE_CXX_GLOBAL="${_CMAKE_CXX_GLOBAL} -DCMAKE_CXX_COMPILER=clang++${_CCSUFFIX}"

    _LD='lld'
    if [ "${_TOOLCHAIN}" != 'llvm-mingw' ]; then  # llvm-mingw uses these tools by default
      _BINUTILS_PREFIX='llvm-'
      _BINUTILS_SUFFIX="${_CCSUFFIX}"
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -fuse-ld=lld${_CCSUFFIX}"
      if [ "${_HOSTOS}" = 'mac' ] && [ "${_OS}" = 'win' ]; then
        _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} -I${_SYSROOT}/${_TRIPLET}/include"
      fi
    fi
    # Avoid warning, as seen on macOS when doing native builds with Homebrew
    # llvm v16:
    #   ld64.lld: warning: Option `-s' is obsolete. Please modernize your usage.
    #   ld: warning: option -s is obsolete and being ignored
    if [ "${_HOSTOS}" != 'mac' ] || [ "${_OS}" != 'mac' ]; then
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -Wl,-s"  # Omit .buildid segment with the timestamp in it
    fi

    if [ "${_OS}" = 'linux' ]; then
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -Wl,--build-id=none"  # Omit build-id
    fi

    # Avoid warnings when passing C compiler options to the linker.
    # Use it with CMake and OpenSSL's proprietary build system.
    _CFLAGS_GLOBAL_CMAKE="${_CFLAGS_GLOBAL_CMAKE} -Wno-unused-command-line-argument"
  else
    _CC_GLOBAL="${_CCPREFIX}gcc"

    if [ "${_OS}" = 'win' ]; then
      _CC_GLOBAL="${_CC_GLOBAL} -static-libgcc"
      _LDFLAGS_GLOBAL="${_OPTM} ${_LDFLAGS_GLOBAL}"
      # https://lists.ffmpeg.org/pipermail/ffmpeg-devel/2015-September/179242.html
      if [ "${_CPU}" = 'x86' ]; then
        _LDFLAGS_BIN_GLOBAL="${_LDFLAGS_BIN_GLOBAL} -Wl,--pic-executable,-e,_mainCRTStartup"
      else
        _LDFLAGS_BIN_GLOBAL="${_LDFLAGS_BIN_GLOBAL} -Wl,--pic-executable,-e,mainCRTStartup"
      fi
      _CFLAGS_GLOBAL="${_OPTM} ${_CFLAGS_GLOBAL}"
    fi

    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER=${_CCPREFIX}gcc"
    _CMAKE_CXX_GLOBAL="${_CMAKE_CXX_GLOBAL} -DCMAKE_CXX_COMPILER=${_CCPREFIX}g++"

    _LD='ld'
  fi

  _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER_TARGET=${_TRIPLET}"
  _CMAKE_CXX_GLOBAL="${_CMAKE_CXX_GLOBAL} -DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}"

  # Needed to exclude compiler info from objects, but for our Windows COFF
  # outputs this seems to be a no-op as of llvm/clang 13.x/14.x.
  # Still necessary with GCC 12.1.0 though.
  if [ "${_CC}" = 'gcc' ] && [ "${_TOOLCHAIN}" != 'llvm-apple' ]; then
    _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -fno-ident"
  fi

  export _CFLAGS_GLOBAL_WPICKY
  # Picky compiler warnings as seen in curl CMake/autotools.
  # builds with llvm/clang 15 and gcc 12.2:
  #   https://clang.llvm.org/docs/DiagnosticsReference.html
  #   https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
  _CFLAGS_GLOBAL_WPICKY='-pedantic -Wcast-align -Wconversion -Wdeclaration-after-statement -Wdouble-promotion -Wempty-body -Wendif-labels -Wenum-conversion -Wfloat-equal -Wignored-qualifiers -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wno-format-nonliteral -Wno-long-long -Wno-multichar -Wno-sign-conversion -Wno-system-headers -Wpointer-arith -Wshadow -Wsign-compare -Wstrict-prototypes -Wtype-limits -Wundef -Wunused -Wunused-const-variable -Wvla -Wwrite-strings'
  [ "${_CC}" = 'llvm' ] && _CFLAGS_GLOBAL_WPICKY="${_CFLAGS_GLOBAL_WPICKY} -Wassign-enum -Wcomma -Wextra-semi-stmt -Wshift-sign-overflow -Wshorten-64-to-32"
  [ "${_CC}" = 'gcc'  ] && _CFLAGS_GLOBAL_WPICKY="${_CFLAGS_GLOBAL_WPICKY} -Walloc-zero -Warith-conversion -Warray-bounds=2 -Wduplicated-branches -Wduplicated-cond -Wformat-overflow=2 -Wformat-truncation=1 -Wformat=2 -Wmissing-parameter-type -Wno-pedantic-ms-format -Wnull-dereference -Wold-style-declaration -Wrestrict -Wshift-negative-value -Wshift-overflow=2 -Wstrict-aliasing=3 -fdelete-null-pointer-checks -ftree-vrp"

  # for boringssl
  export _STRIP_BINUTILS=''
  if [ "${_OS}" = 'win' ] && [ "${_CC}" = 'llvm' ]; then
    if [ "${_CPU}" = 'x64' ] || \
       [ "${_CPU}" = 'x86' ]; then
      # Make sure to pick the prefixed binutils strip tool from an unmodified
      # PATH. This avoids picking the llvm-mingw copy using the same name.
      tmp="${_CCPREFIX}strip"
      if command -v "${tmp}" >/dev/null 2>&1; then
        _STRIP_BINUTILS="$(PATH="${_ori_path}" command -v "${tmp}" 2>/dev/null)"
      else
        echo "! Warning: binutils strip tool '${tmp}' not found. BoringSSL libs may not be reproducible."
      fi
    fi
  fi

  export _STRIP
  if [ "${_TOOLCHAIN}" = 'llvm-apple' ]; then
    _STRIP='echo'  # Xcode strip does not support the options we need
  else
    _STRIP="${_BINUTILS_PREFIX}strip${_BINUTILS_SUFFIX}"
  fi
  export _OBJDUMP="${_BINUTILS_PREFIX}objdump${_BINUTILS_SUFFIX}"
  export _READELF="${_BINUTILS_PREFIX}readelf${_BINUTILS_SUFFIX}"
  if [ "${_OS}" = 'win' ]; then
    export RC="${_BINUTILS_PREFIX}windres${_BINUTILS_SUFFIX}"
  fi
  if [ "${_OS}" = 'win' ] && \
     [ "${_CC}" = 'llvm' ] && \
     [ "${_TOOLCHAIN}" != 'llvm-mingw' ] && \
     [ "${_HOSTOS}" = 'linux' ] && \
     [ -n "${_BINUTILS_SUFFIX}" ]; then
    # FIXME: llvm-windres present, but unable to find its clang counterpart
    #        when suffixed:
    #          llvm-windres-16 -O coff  --target=pe-x86-64 -I../include -i libcurl.rc -o x86_64-w64-windows-gnu/libcurl.res
    #          llvm-rc: Unable to find clang, skipping preprocessing.
    #          Pass --no-preprocess to disable preprocessing. This will be an error in the future.
    #          https://reviews.llvm.org/D100755
    #          https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-rc/llvm-rc.cpp
    #          https://github.com/msys2/MINGW-packages/discussions/8736
    #        Partially fixed in v16.0.2, additional fix pending for v17.0.0:
    #          https://reviews.llvm.org/D157241
    #          https://github.com/curl/curl-for-win/commit/caaae171ac43af5b883403714dafd42030d8de61
    RC="$(pwd)/${RC}"
    ln -s -f "/usr/bin/${_BINUTILS_PREFIX}rc${_BINUTILS_SUFFIX}" "${RC}"
    # llvm-windres/llvm-rc wants to find clang on the same path as itself
    # (or in PATH), with the hard-wired name of clang (or <TRIPLET>-clang,
    # or clang-cl). Workaround: create an alias for it:
    ln -s -f "/usr/bin/clang${_CCSUFFIX}" "$(pwd)/clang"
  fi
  export AR="${_BINUTILS_PREFIX}ar${_BINUTILS_SUFFIX}"
  export NM="${_BINUTILS_PREFIX}nm${_BINUTILS_SUFFIX}"
  export RANLIB="${_BINUTILS_PREFIX}ranlib${_BINUTILS_SUFFIX}"

  # ar wrapper to normalize created libs
  if [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ]; then
    export AR_NORMALIZE
    AR_NORMALIZE="$(pwd)/ar-wrapper-normalize"
    {
      echo '#!/bin/sh -e'
      echo "'${AR}' \"\$@\""
      echo "'$(pwd)/_clean-lib.sh' --ar '${AR}' \"\$@\""
    } > "${AR_NORMALIZE}"
    chmod +x "${AR_NORMALIZE}"
  fi

  if [ "${_OS}" = 'win' ] && [ "${_HOSTOS}" = 'mac' ]; then
    if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${CW_LLVM_MINGW_PATH}/bin/${AR}"
    elif [ "${_CC}" = 'llvm' ]; then
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${_MAC_LLVM_PATH}/${AR}"
    else
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${_SYSROOT}/bin/${AR}"
    fi
  fi

  if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
    _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -rtlib=compiler-rt"
    # `-Wc,...` is necessary for libtool to pass this option to the compiler
    # at link-time. Otherwise libtool strips it.
    #   https://www.gnu.org/software/libtool/manual/html_node/Stripped-link-flags.html
    _LDFLAGS_GLOBAL_AUTOTOOLS="${_LDFLAGS_GLOBAL_AUTOTOOLS} -Wc,-rtlib=compiler-rt"
    _LDFLAGS_CXX_GLOBAL="${_LDFLAGS_CXX_GLOBAL} -stdlib=libc++"
  else
    if [ "${_OS}" = 'win' ]; then
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -static-libgcc"
      _LDFLAGS_CXX_GLOBAL="${_LDFLAGS_CXX_GLOBAL} -static-libstdc++"
    fi
  fi

  _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --prefix=${_PREFIX} --disable-dependency-tracking --disable-silent-rules"

  # Unified, per-target package: Initialize
  export _UNIPKG="curl-${CURL_VER_}${_REVSUFFIX}${_PKGSUFFIX}${_FLAV}"
  rm -r -f "${_UNIPKG:?}"
  mkdir -p "${_UNIPKG}"
  export _UNIMFT="${_UNIPKG}/BUILD-MANIFEST.txt"

  # Detect versions
  clangver=''
  [ "${_CC}" = 'llvm' ] && clangver="clang ${ccver}"

  mingwver=''
  mingwurl=''
  if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
    mingwver='llvm-mingw'
    [ -f "${mingwver}/__url__.txt" ] && mingwurl=" $(cat "${mingwver}/__url__.txt")"
    mingwver="${mingwver} ${CW_LLVM_MINGW_VER_:-?}"
    versuffix="${versuffix_llvm_mingw}"
  elif [ "${_OS}" = 'win' ]; then
    case "${_HOSTOS}" in
      mac)
        mingwver="$(HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew info --json=v2 --formula mingw-w64 | jq --raw-output '.formulae[] | select(.name == "mingw-w64") | .versions.stable')";;
      linux)
        [ -n "${mingwver}" ] || mingwver="$(dpkg   --status       mingw-w64-common)"
        [ -n "${mingwver}" ] || mingwver="$(rpm    --query        mingw64-crt)"
        [ -n "${mingwver}" ] || mingwver="$(pacman --query --info mingw-w64-crt)"
        [ -n "${mingwver}" ] && mingwver="$(printf '%s' "${mingwver}" | grep -a '^Version' | grep -a -m 1 -o -E '[0-9.-]+')"
        ;;
    esac
    [ -n "${mingwver}" ] && mingwver="mingw-w64 ${mingwver}"
    versuffix="${versuffix_non_llvm_mingw}"
  else
    versuffix=''
  fi

  binver=''
  if [ "${_CC}" = 'gcc' ] && [ "${_STRIP}" != 'echo' ]; then
    binver="binutils $("${_STRIP}" --version | grep -m1 -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  elif [ -n "${_STRIP_BINUTILS}" ] && \
       [ "${_OPENSSL}" = 'boringssl' ]; then
    binver="binutils $("${_STRIP_BINUTILS}" --version | grep -m1 -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  fi

  nasmver=''
  if [ "${_OPENSSL}" = 'boringssl' ]; then
    nasmver="nasm $(nasm --version | grep -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  fi

  gccver=''
  [ "${_CC}" = 'llvm' ] || gccver="gcc ${ccver}"

  {
    [ -n "${_COMMIT}" ]  && echo ".${_SELF} ${_COMMIT_SHORT}"
    [ -n "${clangver}" ] && echo ".${clangver}${versuffix}"
    [ -n "${gccver}" ]   && echo ".${gccver}${versuffix}"
    [ -n "${mingwver}" ] && echo ".${mingwver}${versuffix}"
    [ -n "${binver}" ]   && echo ".${binver}"
    [ -n "${nasmver}" ]  && echo ".${nasmver}"
  } >> "${_BLD}"

  {
    [ -n "${_COMMIT}" ]  && echo ".${_SELF} ${_COMMIT_SHORT} ${_TAR}"
    [ -n "${clangver}" ] && echo ".${clangver}${versuffix}"
    [ -n "${gccver}" ]   && echo ".${gccver}${versuffix}"
    [ -n "${mingwver}" ] && echo ".${mingwver}${mingwurl}${versuffix}"
    [ -n "${binver}" ]   && echo ".${binver}"
    [ -n "${nasmver}" ]  && echo ".${nasmver}"
  } >> "${_URLS}"

  {
    [ -n "${clangver}" ] && echo ".${clangver}"
    [ -n "${gccver}" ]   && echo ".${gccver}"
    [ -n "${mingwver}" ] && echo ".${mingwver}${mingwurl}"
  } >> "${_UNIMFT}"

  bld zlib                 "${ZLIB_VER_}"
  bld zlibng             "${ZLIBNG_VER_}" zlib
  bld zstd                 "${ZSTD_VER_}"
  bld brotli             "${BROTLI_VER_}"
  bld cares               "${CARES_VER_}"
  bld libunistring "${LIBUNISTRING_VER_}"
  bld libiconv         "${LIBICONV_VER_}"
  bld libidn2           "${LIBIDN2_VER_}"
  bld libpsl             "${LIBPSL_VER_}"
  bld nghttp3           "${NGHTTP3_VER_}"
  bld wolfssl           "${WOLFSSL_VER_}"
  bld mbedtls           "${MBEDTLS_VER_}"
  bld boringssl       "${BORINGSSL_VER_}"
  bld libressl         "${LIBRESSL_VER_}"
  bld openssl           "${OPENSSL_VER_}"
  bld quictls           "${QUICTLS_VER_}" openssl
  bld gsasl               "${GSASL_VER_}"
  bld ngtcp2             "${NGTCP2_VER_}"
  bld nghttp2           "${NGHTTP2_VER_}"
  bld wolfssh           "${WOLFSSH_VER_}"
  bld libssh             "${LIBSSH_VER_}"
  bld libssh2           "${LIBSSH2_VER_}"
  bld cacert             "${CACERT_VER_}"
  bld curl                 "${CURL_VER_}"

  # Unified, per-target package: Build
  export _NAM="${_UNIPKG}"
  export _VER="${CURL_VER_}"
  export _OUT="${_UNIPKG}"
  export _BAS="${_UNIPKG}"
  export _DST="${_UNIPKG}"

  _ref='curl/CHANGES'

  if [ ! -f "${_ref}" ]; then
    # This can happen with CW_BLD partial builds.
    echo '! WARNING: curl build missing. Skip packaging.'
  else
    touch -c -r "${_ref}" "${_UNIMFT}"

    (
      cd "${_DST}"
      set +x
      _fn='BUILD-HASHES.txt'
      {
        find . -type f | grep -a -E '/(bin|include|lib)/' | sort | while read -r f; do
          openssl dgst -sha256 "${f}"
        done
      } | sed 's/^SHA256/SHA2-256/g' > "${_fn}"
      touch -c -r "../${_ref}" "${_fn}"
    )

    if [ "${_OS}" = 'win' ]; then
      _fn="${_DST}/BUILD-README.url"
      cat <<EOF > "${_fn}"
[InternetShortcut]
URL=${_URL_BASE}
EOF
      unix2dos --quiet --keepdate "${_fn}"
    elif [ "${_OS}" = 'mac' ]; then
      _fn="${_DST}/BUILD-README.webloc"
      cat <<EOF > "${_fn}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>URL</key>
  <string>${_URL_BASE}</string>
</dict>
</plist>
EOF
    else
      _fn="${_DST}/BUILD-README-URL.txt"
      echo "${_URL_BASE}" > "${_fn}"
    fi
    touch -c -r "${_ref}" "${_fn}"

    ./_pkg.sh "${_ref}"
  fi
}

# Build binaries
if [ "${_OS}" = 'win' ]; then
  if [ "${_BRANCH#*a64*}" = "${_BRANCH}" ] && \
     [ "${_BRANCH#*x86*}" = "${_BRANCH}" ]; then
    build_single_target x64
  fi
  if [ "${_BRANCH#*x64*}" = "${_BRANCH}" ] && \
     [ "${_BRANCH#*x86*}" = "${_BRANCH}" ]; then
    build_single_target a64
  fi
  if [ "${_BRANCH#*x64*}" = "${_BRANCH}" ] && \
     [ "${_BRANCH#*a64*}" = "${_BRANCH}" ]; then
    build_single_target x86
  fi
else
  [ "${unamem}" = 'i686'    ] && cpu='x86'
  [ "${unamem}" = 'x86_64'  ] && cpu='x64'
  [ "${unamem}" = 'aarch64' ] && cpu='a64'
  build_single_target "${cpu}"
fi

case "${_HOSTOS}" in
  mac)   rm -f -P "${SIGN_CODE_KEY}";;
  linux) [ -w "${SIGN_CODE_KEY}" ] && srm "${SIGN_CODE_KEY}";;
esac
rm -f "${SIGN_CODE_KEY}"

# Upload/deploy binaries
. ./_ul.sh
