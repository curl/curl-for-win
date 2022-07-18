#!/bin/sh

# Copyright 2015-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
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
#        noh3       build without HTTP/3 (QUIC) support (select stock OpenSSL instead of its QUIC fork)
#        nobrotli   build without brotli
#        noftp      build without FTP/FTPS support
#        boringssl  build with BoringSSL
#        libressl   build with LibreSSL
#        schannel   build with Schannel
#        mini       build with less features, see README.md
#        micro      build with less features, see README.md
#        nano       build with less features, see README.md
#        pico       build with less features, see README.md
#        a64        build ARM64 target only
#        x64        build x64 target only
#        x86        build x86 target only
#        msvcrt     build against msvcrt instead of UCRT
#        gcc        build with GCC (use clang if not specified)
#        unicode    build curl in UNICODE mode [EXPERIMENTAL]
#
# CW_JOBS
#      Number of parallel make jobs. Default: 2
#
# CW_CCSUFFIX
#      clang suffix. E.g. '-8' for clang-8.
#      Optional. Default: (empty)
#
# SIGN_CODE_GPG_PASS, SIGN_CODE_KEY_PASS: for code signing
# SIGN_PKG_KEY_ID, SIGN_PKG_GPG_PASS, SIGN_PKG_KEY_PASS: for package signing
# DEPLOY_GPG_PASS, DEPLOY_KEY_PASS: for publishing results
#      Secrets used for the above operations.
#      Optional. Skipping any operation missing a secret.

# TODO:
#   - Change default TLS to BoringSSL? with OPENSSL_SMALL?
#   - Drop XP compatibility for x86 builds also
#   - Drop x86 builds
#   - Make -nobrotli the default?
#   - Enable Control Flow Guard (once FLOSS toolchains support it): -ehcontguard (requires LLVM 13.0.0)
#   - LLVM -mretpoline

# Resources:
#   - https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html
#   - https://github.com/mstorsjo/llvm-mingw
#   - https://github.com/llvm/llvm-project
#   - https://salsa.debian.org/pkg-llvm-team
#   - https://git.code.sf.net/p/mingw-w64/mingw-w64 / https://github.com/mirror/mingw-w64
#   - https://sourceware.org/git/binutils-gdb.git
#   - https://github.com/netwide-assembler/nasm

# Supported build tools:
#
#   zlib          cmake
#   zstd          cmake
#   brotli        cmake
#   cares         cmake
#   libunistring  autotools
#   libiconv      autotools
#   libidn2       autotools
#   libpsl        autotools
#   libgsasl      autotools
#   nghttp2       cmake
#   nghttp3       cmake
#   ngtcp2        cmake
#   mbedtls       cmake
#   openssl       proprietary
#   boringssl     cmake
#   libressl      autotools, cmake
#   libssh        cmake
#   libssh2       autotools, cmake
#   curl          cmake, autotools, Makefile.m32

cd "$(dirname "$0")"

export LC_ALL=C
export LC_MESSAGES=C
export LANG=C

export GREP_OPTIONS=
export ZIPOPT=
export ZIP=

readonly _LOG='logurl.txt'
readonly _SELF='curl-for-win'
if [ -n "${APPVEYOR_ACCOUNT_NAME:-}" ]; then
  # https://www.appveyor.com/docs/environment-variables/
  _SLUG="${APPVEYOR_REPO_NAME}"
  _LOGURL="${APPVEYOR_URL}/project/${APPVEYOR_ACCOUNT_NAME}/${APPVEYOR_PROJECT_SLUG}/build/${APPVEYOR_BUILD_VERSION}/job/${APPVEYOR_JOB_ID}"
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
  _COMMIT="$(git rev-parse --verify HEAD)"
  _COMMIT_SHORT="$(git rev-parse --short=8 HEAD)"
fi
echo "${_LOGURL}" | tee "${_LOG}"

export _BRANCH="${APPVEYOR_REPO_BRANCH:-}${CI_COMMIT_REF_NAME:-}${GITHUB_REF:-}${CW_CONFIG:-}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD)"
[ -n "${_BRANCH}" ] || _BRANCH='main'
if command -v git >/dev/null 2>&1; then
  _URL_BASE="$(git ls-remote --get-url | sed 's/\.git$//')"
  _URL_FULL="${_URL_BASE}/tree/${_COMMIT}"
  _TAR="${_URL_BASE}/archive/${_COMMIT}.tar.gz"
else
  _URL_BASE="https://github.com/${_SLUG}"
  _URL_FULL="${_URL_BASE}"
  _TAR="${_URL_BASE}/archive/refs/heads/${_BRANCH}.tar.gz"
fi

[ -n "${CW_CCSUFFIX:-}" ] || CW_CCSUFFIX=''

export _CC='clang'
[ ! "${_BRANCH#*gcc*}" = "${_BRANCH}" ] && _CC='gcc'

export _CRT='ucrt'
[ ! "${_BRANCH#*msvcrt*}" = "${_BRANCH}" ] && _CRT='msvcrt'

if [ -z "${CW_MAP:-}" ]; then
  export CW_MAP='0'
  [ "${_BRANCH#*main*}" = "${_BRANCH}" ] && CW_MAP='1'
fi

export _JOBS=2
[ -n "${CW_JOBS:-}" ] && _JOBS="${CW_JOBS}"

# Detect host OS
export _OS
case "$(uname)" in
  *_NT*)   _OS='win';;
  Linux*)  _OS='linux';;
  Darwin*) _OS='mac';;
  *BSD)    _OS='bsd';;
  *)       _OS='unrecognized';;
esac

# Form suffix for alternate builds
export _FLAV=''
if [ "${_BRANCH#*nano*}" != "${_BRANCH}" ]; then
  _FLAV='-nano'
elif [ "${_BRANCH#*micro*}" != "${_BRANCH}" ]; then
  _FLAV='-micro'
elif [ "${_BRANCH#*mini*}" != "${_BRANCH}" ]; then
  _FLAV='-mini'
elif [ "${_BRANCH#*noh3*}" != "${_BRANCH}" ]; then
  _FLAV='-noh3'
fi

# For 'configure'-based builds.
# This is more or less guesswork and this warning remains:
#    `configure: WARNING: using cross tools not prefixed with host triplet`
# Even with `_CCPREFIX` provided.
if [ "${_OS}" != 'win' ]; then
  # https://clang.llvm.org/docs/CrossCompilation.html
  case "${_OS}" in
    win)   _CROSS_HOST="$(uname -m)-pc-mingw32";;
    linux) _CROSS_HOST="$(uname -m)-pc-linux";;
    bsd)   _CROSS_HOST="$(uname -m)-pc-bsd";;
    mac)   _CROSS_HOST="$(uname -m)-apple-darwin";;
  esac
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

rm -f ./*-*-mingw*.*
rm -f hashes.txt "${_BLD}" "${_URLS}"

touch hashes.txt "${_BLD}" "${_URLS}"

. ./_versions.sh

# Revision suffix used in package filenames
export _REVSUFFIX="${_REV}"; [ -z "${_REVSUFFIX}" ] || _REVSUFFIX="_${_REVSUFFIX}"

# Download sources
./_dl.sh

# Find and setup llvm-mingw downloaded above.
if [ -z "${CW_LLVM_MINGW_PATH:-}" ] && \
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

if [ -s "${SIGN_CODE_KEY}" ]; then
  osslsigncode --version  # We need 2.2 or newer
fi

_ori_path="${PATH}"

bld() {
  pkg="$1"
  if [ -z "${CW_BLD:-}" ] || echo "-${CW_BLD}-" | grep -q -F -- "-${pkg}-"; then
    shift

    pkgori="${pkg}"
    [ -n "${2:-}" ] && pkg="$2"
    # allow selecting an alternate build tool
    withbuildtool="$(echo "${CW_BLD:-}" | \
      grep -a -o -E "${pkg}-(cmake|autotools|make|m32)" || true)"
    if [ -n "${withbuildtool}" ] && [ -f "${withbuildtool}.sh" ]; then
      pkg="${withbuildtool}"
    fi

    time "./${pkg}.sh" "$1" "${pkgori}"

    if [ "${CW_DEV_MOVEAWAY:-}" = '1' ] && [ "${pkg}" != "${pkgori}" ]; then
      mv -n "${pkgori}" "${pkg}"
    fi
  fi
}

build_single_target() {
  export _CPU="$1"

  use_llvm_mingw=0
  versuffix_llvm_mingw=''
  if [ "${CW_LLVM_MINGW_ONLY:-}" = '1' ]; then
    use_llvm_mingw=1
  # llvm-mingw is required for x64 (to avoid pthread link bug with BoringSSL),
  # but for consistency, use it for all targets when building with BoringSSL.
  elif [ -d boringssl ] && [ "${_CRT}" = 'ucrt' ]; then
    use_llvm_mingw=1
  elif [ "${_CPU}" = 'a64' ]; then
    use_llvm_mingw=1
    versuffix_llvm_mingw=' (ARM64)'
  fi

  # Toolchain
  export _TOOLCHAIN
  if [ "${use_llvm_mingw}" = '1' ]; then
    if [ "${_CC}" != 'clang' ] || \
       [ "${_CRT}" != 'ucrt' ] || \
       [ -z "${CW_LLVM_MINGW_PATH:-}" ]; then
      echo "! WARNING: '${_BRANCH}/${_CPU}' builds require clang, UCRT and CW_LLVM_MINGW_PATH. Skipping."
      return
    fi
    _TOOLCHAIN='llvm-mingw'
  else
    _TOOLCHAIN='mingw-w64'
  fi

  export _TRIPLET=''
  _SYSROOT=''

  export _CCPREFIX=
  export _MAKE='make'
  export _WINE=''

  # GCC-specific machine selection option
  [ "${_CPU}" = 'x86' ] && _OPTM='-m32'
  [ "${_CPU}" = 'x64' ] && _OPTM='-m64'
  [ "${_CPU}" = 'a64' ] && _OPTM='-marm64pe'

  [ "${_CPU}" = 'x86' ] && _machine='i686'
  [ "${_CPU}" = 'x64' ] && _machine='x86_64'
  [ "${_CPU}" = 'a64' ] && _machine='aarch64'

  export _CURL_DLL_SUFFIX=''
  [ "${_CPU}" = 'x64' ] && _CURL_DLL_SUFFIX="-${_CPU}"
  [ "${_CPU}" = 'a64' ] && _CURL_DLL_SUFFIX="-arm64"

  export _PKGSUFFIX
  [ "${_CPU}" = 'x86' ] && _PKGSUFFIX='-win32-mingw'
  [ "${_CPU}" = 'x64' ] && _PKGSUFFIX='-win64-mingw'
  [ "${_CPU}" = 'a64' ] && _PKGSUFFIX='-win64a-mingw'

  # Reset for each target
  PATH="${_ori_path}"

  if [ "${_OS}" = 'win' ]; then
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

    # Install required component
    pip3 --version
    pip3 --disable-pip-version-check --no-cache-dir install --user "pefile==${PEFILE_VER_}"
  else
    if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
      export PATH="${CW_LLVM_MINGW_PATH}/bin:${_ori_path}"
    elif [ "${_CC}" = 'clang' ] && [ "${_OS}" = 'mac' ]; then
      _MAC_LLVM_PATH='/usr/local/opt/llvm/bin'
      export PATH="${_MAC_LLVM_PATH}:${_ori_path}"
    fi
    _TRIPLET="${_machine}-w64-mingw32"
    # Prefixes do not work with MSYS2/mingw-w64, because `ar`, `nm` and
    # `ranlib` are missing from them. They are accessible either _without_
    # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
    _CCPREFIX="${_TRIPLET}-"
    # mingw-w64 sysroots
    if [ "${_TOOLCHAIN}" != 'llvm-mingw' ]; then
      if [ "${_OS}" = 'mac' ]; then
        _SYSROOT="/usr/local/opt/mingw-w64/toolchain-${_machine}"
      elif [ "${_OS}" = 'linux' ]; then
        _SYSROOT="/usr/${_TRIPLET}"
      fi
    fi

    # TODO: Run ARM64 targets on ARM64 linux/mac hosts?
    _WINE='echo'
    if [ "${_OS}" = 'linux' ]; then
      # Execute CPU-native targets only
      if [ "${_CPU}" = 'x64' ] && \
         [ "$(uname -m)" = 'x86_64' ]; then
        _WINE='wine64'
      fi
    elif [ "${_OS}" = 'mac' ]; then
      if [ "${_CPU}" = 'x64' ] && \
         [ "$(uname -m)" = 'x86_64' ] && \
         [ "$(sysctl -i -n sysctl.proc_translated)" != '1' ]; then
        _WINE='wine64'
      fi
    elif [ "${_OS}" = 'win' ]; then
      _WINE='wine'  # TODO: What targets can an ARM64 host run? Can an x64 host run ARM64 targets?
    fi
  fi

  if [ "${_CC}" = 'clang' ]; then
    # We do not use old mingw toolchain versions when building with clang,
    # so this is safe:
    _CCVER='99'
  else
    _CCVER="$(printf '%02d' \
      "$("${_CCPREFIX}gcc" -dumpversion | grep -a -o -E '^[0-9]+')")"

    # Create specs files that overrides msvcrt with ucrt. We need this
    # for gcc when building against UCRT.
    if [ "${_CRT}" = 'ucrt' ]; then
      # https://stackoverflow.com/questions/57528555/how-do-i-build-against-the-ucrt-with-mingw-w64
      _GCCSPECS="$(realpath gcc-specs-ucrt)"
      "${_CCPREFIX}gcc" -dumpspecs | sed 's/-lmsvcrt/-lucrt/g' > "${_GCCSPECS}"
    fi
  fi

  # Setup common toolchain configuration options

  export _TOP; _TOP="$(pwd)"  # Must be an absolute path
  export _PKGDIR="${_CPU}-${_CRT}"
  _PREFIX='/usr'
  export _PP="${_PKGDIR}${_PREFIX}"
  export _BLDDIR='bld'
  export _CC_GLOBAL=''
  export _CFLAGS_GLOBAL=''
  export _CPPFLAGS_GLOBAL=''
  export _CXXFLAGS_GLOBAL=''
  export _RCFLAGS_GLOBAL=''
  export _LDFLAGS_GLOBAL=''
  export _LDFLAGS_CXX_GLOBAL=''
  export _LIBS_GLOBAL=''
  export _CONFIGURE_GLOBAL=''
  export _CMAKE_GLOBAL='-Wno-dev -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release'
  export _CMAKE_CXX_GLOBAL=''

  # for CMake and openssl
  unset CC

  [ "${_CPU}" = 'x86' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=pe-i386"
  [ "${_CPU}" = 'x64' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=pe-x86-64"
  [ "${_CPU}" = 'a64' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=${_TRIPLET}"  # llvm windres supports triplets here. https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-rc/llvm-rc.cpp

  if [ "${_OS}" = 'win' ]; then
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -GMSYS Makefiles"
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

  _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --build=${_CROSS_HOST} --host=${_TRIPLET}"
  [ "${_CPU}" = 'x86' ] && _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -fno-asynchronous-unwind-tables"

  export _LD
  _BINUTILS_PREFIX="${_CCPREFIX}"
  if [ "${_CC}" = 'clang' ]; then
    _CC_GLOBAL="clang${CW_CCSUFFIX} --target=${_TRIPLET}"
    _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --target=${_TRIPLET}"
    if [ -n "${_SYSROOT}" ]; then
      _CC_GLOBAL="${_CC_GLOBAL} --sysroot=${_SYSROOT}"
      _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --with-sysroot=${_SYSROOT}"
    fi
    if [ "${_OS}" = 'linux' ]; then
      # We used to pass this via CFLAGS for CMake to make it detect clang, so
      # we need to pass this via CMAKE_C_FLAGS, though meant for the linker.
      if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
        _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -L${CW_LLVM_MINGW_PATH}/${_TRIPLET}/lib"
      else
        # https://packages.debian.org/testing/amd64/gcc-mingw-w64-x86-64-posix/filelist
        tmp="$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
        _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -L${tmp}"
        _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} -I${tmp}/include/c++"
        _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} -I${tmp}/include/c++/${_TRIPLET}"
        _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} -I${tmp}/include/c++/backward"
      fi
    fi
    if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
      # Turns out autotools/libtool (in curl?) is overbusy/stupid enough to
      # delete LDFLAGS it does not recognize. This can explain why nothing
      # worked before moving `--target=` and `--sysroot=` into CC from LDFLAGS.
      # Do the same with this option, to avoid yet another libtool fail.
      # autotools and OpenSSL use this variable, CMake does not.
      _CC_GLOBAL="${_CC_GLOBAL} -rtlib=compiler-rt"
    fi

    # This does not work yet, due to:
    #   /usr/local/bin/x86_64-w64-mingw32-ld: asyn-thread.o:asyn-thread.c:(.rdata$.refptr.__guard_dispatch_icall_fptr[.refptr.__guard_dispatch_icall_fptr]+0x0): undefined reference to `__guard_dispatch_icall_fptr'
  # _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -Xclang -cfguard"
  # _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -Xlinker -guard:cf"

    if [ -n "${_SYSROOT}" ]; then
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_SYSROOT=${_SYSROOT}"
    fi
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER_TARGET=${_TRIPLET}"
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER=clang${CW_CCSUFFIX}"
    _CMAKE_CXX_GLOBAL="${_CMAKE_CXX_GLOBAL} -DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}"
    _CMAKE_CXX_GLOBAL="${_CMAKE_CXX_GLOBAL} -DCMAKE_CXX_COMPILER=clang++${CW_CCSUFFIX}"

    _LD='lld'
    if [ "${_TOOLCHAIN}" != 'llvm-mingw' ]; then  # llvm-mingw uses these tools by default
      _BINUTILS_PREFIX='llvm-'
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -fuse-ld=lld"
      if [ "${_OS}" = 'mac' ]; then
        _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} -I${_SYSROOT}/${_TRIPLET}/include"
      fi
    fi
    _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -Wl,-s"  # Omit .buildid segment with the timestamp in it
  else
    _CC_GLOBAL="${_CCPREFIX}gcc -static-libgcc"
    _LDFLAGS_GLOBAL="${_OPTM} ${_LDFLAGS_GLOBAL}"
    _CFLAGS_GLOBAL="${_OPTM} ${_CFLAGS_GLOBAL}"

    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER=${_CCPREFIX}gcc"
    _CMAKE_CXX_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_CXX_COMPILER=${_CCPREFIX}g++"

    _LD='ld'
  fi

  # Needed to exclude compiler info from objects, but for our Windows COFF
  # outputs this seems to be a no-op as of clang 13.x/14.x.
  # Still necessary with GCC 12.1.0 though.
  if [ "${_CC}" = 'gcc' ]; then
    _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -fno-ident"
  fi

  # for boringssl
  export _STRIP_BINUTILS=''
  if [ "${_CC}" = 'clang' ]; then
    if [ "${_CPU}" = 'x64' ] || \
       [ "${_CPU}" = 'x86' ]; then
      # Make sure to pick the prefixed binutils strip tool from an unmodified
      # PATH. This avoids picking the llvm-mingw copy using the same name.
      tmp="${_CCPREFIX}strip"
      if command -v "${tmp}" >/dev/null 2>&1; then
        _STRIP_BINUTILS="$(PATH="${_ori_path}" which "${tmp}")"
      else
        echo "! Warning: binutils strip tool '${tmp}' not found. BoringSSL libs may not be fully reproducible."
      fi
    fi
  fi

  export _STRIP="${_BINUTILS_PREFIX}strip"
  export _OBJDUMP="${_BINUTILS_PREFIX}objdump"
  export RC
  if [ "${_CC}" = 'clang' ] && \
     [ "${_TOOLCHAIN}" != 'llvm-mingw' ] && \
     [ "${_OS}" = 'linux' ] && \
     [ -x /usr/bin/llvm-rc ]; then
    # FIXME: llvm-windres alias (to llvm-rc) missing from current debian:testing.
    #        Workaround: Create an alias and use to that.
    #        https://packages.debian.org/bookworm/amd64/llvm/filelist
    RC="$(pwd)/llvm-windres"
    ln -s -f /usr/bin/llvm-rc "${RC}"
  else
    RC="${_BINUTILS_PREFIX}windres"
  fi
  export AR="${_BINUTILS_PREFIX}ar"
  export NM="${_BINUTILS_PREFIX}nm"
  export RANLIB="${_BINUTILS_PREFIX}ranlib"

  # In some environments, we need to pair up llvm-windres with the mingw-w64
  # include dir, and/or we need to pass it the target platform. Some builds
  # do not (yet) support adding custom options. Add a wrapper for these
  # builds that calls llvm-windres with the necessary custom options.
  export _RC_WRAPPER=''
  if [ "${_CC}" = 'clang' ] && \
     [ "${_TOOLCHAIN}" != 'llvm-mingw' ] && \
     [ -n "${_RCFLAGS_GLOBAL}" ]; then
    _RC_WRAPPER="$(pwd)/llvm-windres-wrapper"
    {
      echo "#!/bin/sh -e"
      echo "'${RC}' ${_RCFLAGS_GLOBAL} \"\$@\""
    } > "${_RC_WRAPPER}"
    chmod +x "${_RC_WRAPPER}"
  fi

  # ar wrapper to normalize created libs
  if [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ]; then
    export AR_NORMALIZE
    AR_NORMALIZE="$(pwd)/ar-wrapper-normalize"
    {
      echo "#!/bin/sh -e"
      echo "'${AR}' \"\$@\""
      echo "'$(pwd)/_libclean.sh' --ar '${AR}' \"\$@\""
    } > "${AR_NORMALIZE}"
    chmod +x "${AR_NORMALIZE}"
  fi

  if [ "${_OS}" = 'mac' ]; then
    if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${CW_LLVM_MINGW_PATH}/bin/${AR}"
    elif [ "${_CC}" = 'clang' ]; then
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${_MAC_LLVM_PATH}/${AR}"
    else
      _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${_SYSROOT}/bin/${AR}"
    fi
  fi

  if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
    _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -rtlib=compiler-rt"
    _LDFLAGS_CXX_GLOBAL="${_LDFLAGS_CXX_GLOBAL} -stdlib=libc++"
  else
    _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -static-libgcc"
    _LDFLAGS_CXX_GLOBAL="${_LDFLAGS_CXX_GLOBAL} -static-libstdc++"
  fi

  _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --prefix=${_PREFIX} --disable-dependency-tracking --disable-silent-rules"

  # Unified, per-target package: Initialize
  export _UNIPKG="curl-${CURL_VER_}${_REVSUFFIX}${_PKGSUFFIX}${_FLAV}"
  rm -r -f "${_UNIPKG:?}"
  mkdir -p "${_UNIPKG}"
  export _UNIMFT="${_UNIPKG}/BUILD-MANIFEST.txt"

  # Detect versions
  clangver=''
  [ "${_CC}" = 'clang' ] && clangver="clang$("clang${CW_CCSUFFIX}" --version | grep -o -a -E ' [0-9]*\.[0-9]*[\.][0-9]*')"

  versuffix=''
  mingwver=''
  mingwurl=''
  if [ "${_TOOLCHAIN}" = 'llvm-mingw' ]; then
    mingwver='llvm-mingw'
    [ -f "${mingwver}/__url__.txt" ] && mingwurl=" $(cat "${mingwver}/__url__.txt")"
    mingwver="${mingwver} ${CW_LLVM_MINGW_VER_:-?}"
    versuffix="${versuffix_llvm_mingw}"
  else
    case "${_OS}" in
      mac)
        mingwver="$(brew info --json=v2 --formula mingw-w64 | jq --raw-output '.formulae[] | select(.name == "mingw-w64") | .versions.stable')";;
      linux)
        [ -n "${mingwver}" ] || mingwver="$(dpkg   --status       mingw-w64-common)"
        [ -n "${mingwver}" ] || mingwver="$(rpm    --query        mingw64-crt)"
        [ -n "${mingwver}" ] || mingwver="$(pacman --query --info mingw-w64-crt)"
        [ -n "${mingwver}" ] && mingwver="$(printf '%s' "${mingwver}" | grep -a '^Version' | grep -a -m 1 -o -E '[0-9.-]+')"
        ;;
    esac
    [ -n "${mingwver}" ] && mingwver="mingw-w64 ${mingwver}"
  fi

  binver=''
  if [ "${_CC}" = 'gcc' ]; then
    binver="binutils $("${_STRIP}" --version | grep -m1 -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  elif [ -n "${_STRIP_BINUTILS}" ] && \
       [ -d boringssl ]; then
    binver="binutils $("${_STRIP_BINUTILS}" --version | grep -m1 -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  fi

  nasmver=''
  if [ -d boringssl ]; then
    nasmver="nasm $(nasm --version | grep -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"
  fi

  gccver=''
  [ "${_CC}" = 'clang' ] || gccver="gcc $("${_CCPREFIX}gcc" -dumpversion)"

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
  bld zstd                 "${ZSTD_VER_}"
  bld brotli             "${BROTLI_VER_}"
  bld cares               "${CARES_VER_}"
  bld libunistring "${LIBUNISTRING_VER_}"
  bld libiconv         "${LIBICONV_VER_}"
  bld libidn2           "${LIBIDN2_VER_}"
  bld libpsl             "${LIBPSL_VER_}"
  bld libgsasl         "${LIBGSASL_VER_}"
  bld nghttp3           "${NGHTTP3_VER_}"
  bld mbedtls           "${MBEDTLS_VER_}"
  bld boringssl       "${BORINGSSL_VER_}"
  bld libressl         "${LIBRESSL_VER_}"
  bld openssl           "${OPENSSL_VER_}"
  bld openssl-quic "${OPENSSL_QUIC_VER_}" openssl
  bld ngtcp2             "${NGTCP2_VER_}"
  bld nghttp2           "${NGHTTP2_VER_}"
  bld libssh             "${LIBSSH_VER_}"
  bld libssh2           "${LIBSSH2_VER_}"
  bld curl                 "${CURL_VER_}"

  # Unified, per-target package: Build
  export _NAM="${_UNIPKG}"
  export _VER="${CURL_VER_}"
  export _OUT="${_UNIPKG}"
  export _BAS="${_UNIPKG}"
  export _DST="${_UNIPKG}"

  _ref='curl/CHANGES'

  if ! [ -f "${_ref}" ]; then
    # This can happen with CW_BLD partial builds.
    echo '! WARNING: curl is missing. Skip packaging.'
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

    _fn="${_DST}/BUILD-README.url"
    cat <<EOF > "${_fn}"
[InternetShortcut]
URL=${_URL_BASE}
EOF
    unix2dos --quiet --keepdate "${_fn}"
    touch -c -r "${_ref}" "${_fn}"

    ./_pkg.sh "${_ref}"
  fi
}

# Build binaries
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

case "${_OS}" in
  mac)   rm -f -P "${SIGN_CODE_KEY}";;
  linux) [ -w "${SIGN_CODE_KEY}" ] && srm "${SIGN_CODE_KEY}";;
esac
rm -f "${SIGN_CODE_KEY}"

# Upload/deploy binaries
. ./_ul.sh
