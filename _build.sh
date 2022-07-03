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
# CW_CONFIG
#      Build configuration. Certain keywords select certain configurations. E.g.: 'main-micro'.
#      Optional. Default: 'main' (inherited from the active repo branch name)
#
#      Supported keywords:
#        main      production build
#        test      test build (.map files enabled, VirusTotal upload and publishing disabled)
#        dev       development build (use source snapshots instead of stable releases)
#        noh3      build without HTTP/3 (QUIC) support (select stock OpenSSL instead of its QUIC fork)
#        nobrotli  build without brotli
#        noftp     build without FTP/FTPS support
#        libressl  build with LibreSSL instead of OpenSSL
#        schannel  build with Schannel
#        mini      build with less features, see README.md
#        micro     build with less features, see README.md
#        nano      build with less features, see README.md
#        pico      build with less features, see README.md
#        a64       build arm64 target only
#        x64       build x64 target only
#        x86       build x86 target only
#        msvcrt    build against msvcrt instead of UCRT
#        gcc       build with GCC (use clang if not specified)
#        unicode   build curl in UNICODE mode [EXPERIMENTAL]
#
# CW_CCSUFFIX
#      clang suffix. E.g. '-8' for clang-8.
#      Optional. Default: (empty)
#
# SIGN_CODE_GPG_PASS, SIGN_CODE_KEY_PASS: for code signing
# SIGN_PKG_KEY_ID, SIGN_PKG_GPG_PASS, SIGN_PKG_KEY_PASS: for package signing
# VIRUSTOTAL_APIKEY: for VirusTotal uploads
# DEPLOY_GPG_PASS, DEPLOY_KEY_PASS: for publishing results
#      Secrets used for the above operations.
#      Optional. Skipping any operation missing a secret.

# TODO:
#   - Update naming-scheme to make room for arm64 builds:
#       win64 -> win-x64
#       win32 -> win-x86
#             -> win-a64 / win-arm64
#     Needs updating curl-www also.
#   - Add support for arm64 builds (requires UCRT)
#   - Drop XP compatibility for x86 builds also
#   - Drop x86 builds
#   - Make -noftp the default?
#   - Make -nobrotli the default?
#   - Enable Control Flow Guard (once FLOSS toolchains support it): -ehcontguard (requires LLVM 13.0.0)
#   - LLVM -mretpoline
#   - Change default TLS to
#     - Schannel (no QUIC, no TLSv1.3, no TLS-SRP)
#     - LibreSSL (no QUIC, no ed25519 in libssh2)
#     - rustls (experimental, no rand)

# Resources:
#   - https://github.com/mstorsjo/llvm-mingw
#   - https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html

# Supported build tools:
#
#   zlib      cmake
#   brotli    cmake
#   libgsasl  autotools
#   libidn2   autotools
#   nghttp2   cmake
#   nghttp3   cmake
#   ngtcp2    cmake
#   openssl   proprietary
#   libressl  autotools, cmake
#   libssh2   autotools, cmake
#   curl      cmake, autotools, Makefile.m32

cd "$(dirname "$0")"

export LC_ALL=C
export LC_MESSAGES=C
export LANG=C

export GREP_OPTIONS=
export ZIPOPT=
export ZIP=

readonly _LOG='logurl.txt'
if [ -n "${APPVEYOR_ACCOUNT_NAME:-}" ]; then
  # https://www.appveyor.com/docs/environment-variables/
  _LOGURL="${APPVEYOR_URL}/project/${APPVEYOR_ACCOUNT_NAME}/${APPVEYOR_PROJECT_SLUG}/build/${APPVEYOR_BUILD_VERSION}/job/${APPVEYOR_JOB_ID}"
# _LOGURL="${APPVEYOR_URL}/api/buildjobs/${APPVEYOR_JOB_ID}/log"
elif [ -n "${GITHUB_RUN_ID:-}" ]; then
  # https://docs.github.com/actions/reference/environment-variables
  _LOGURL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
elif [ -n "${CI_JOB_ID:-}" ]; then
  # https://docs.gitlab.com/ce/ci/variables/index.html
  _LOGURL="${CI_SERVER_URL}/${CI_PROJECT_PATH}/-/jobs/${CI_JOB_ID}/raw"
else
  _LOGURL=''
fi
echo "${_LOGURL}" | tee "${_LOG}"

export _BRANCH="${APPVEYOR_REPO_BRANCH:-}${CI_COMMIT_REF_NAME:-}${GITHUB_REF:-}${CW_CONFIG:-}"
[ -n "${_BRANCH}" ] || _BRANCH="$(git symbolic-ref --short --quiet HEAD)"
[ -n "${_BRANCH}" ] || _BRANCH='main'
export _URL=''
command -v git >/dev/null 2>&1 && _URL="$(git ls-remote --get-url | sed 's|.git$||')"
[ -n "${_URL}" ] || _URL="https://github.com/${APPVEYOR_REPO_NAME:-}${GITHUB_REPOSITORY:-}"

[ -n "${CW_CCSUFFIX:-}" ] || CW_CCSUFFIX=''

export _CC='clang'
[ ! "${_BRANCH#*gcc*}" = "${_BRANCH}" ] && _CC='gcc'

_CRT='ucrt'
[ ! "${_BRANCH#*msvcrt*}" = "${_BRANCH}" ] && _CRT='msvcrt'

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
    win)   _CROSS_HOST='x86_64-pc-mingw32';;
    linux) _CROSS_HOST='x86_64-pc-linux';;  # x86_64-pc-linux-gnu
    bsd)   _CROSS_HOST='x86_64-pc-bsd';;
    mac)
      if [ "$(uname -m)" = 'arm64' ]; then
        _CROSS_HOST='arm-apple-darwin'
      else
        _CROSS_HOST='x86_64-apple-darwin'
      fi
      ;;
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

rm -f ./*-*-mingw*.*
rm -f hashes.txt
rm -f "${_BLD}"

. ./_versions.sh

# Revision suffix used in package filenames
export _REVSUFFIX="${_REV}"; [ -z "${_REVSUFFIX}" ] || _REVSUFFIX="_${_REVSUFFIX}"

# Download sources
./_dl.sh

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
  # build osslsigncode
  ./osslsigncode.sh "${OSSLSIGNCODE_VER_}"
  ls -l "$(dirname "$0")/osslsigncode-local"*
  "$(dirname "$0")/osslsigncode-local" --version
fi

clangver=''
[ "${_CC}" = 'clang' ] && clangver="clang$("clang${CW_CCSUFFIX}" --version | grep -o -a -E ' [0-9]*\.[0-9]*[\.][0-9]*')"

mingwver=''
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

[ -n "${clangver}" ] && echo ".${clangver}" >> "${_BLD}"
[ -n "${mingwver}" ] && echo ".${mingwver}" >> "${_BLD}"

_ori_path="${PATH}"

bld() {
  pkg="$1"
  if [ -z "${CW_BLD:-}" ] || echo "${CW_BLD}" | grep -q -F "${pkg}"; then
    shift

    pkgori="${pkg}"
    # allow selecting an alternate build tool
    withbuildtool="$(echo "${CW_BLD:-}" | \
      grep -a -o -E "${pkg}-(cmake|autotools|make|m32)" || true)"
    if [ -n "${withbuildtool}" ] && [ -f "${withbuildtool}.sh" ]; then
      pkg="${withbuildtool}"
    fi

    time "./${pkg}.sh" "$@"

    if [ "${CW_DEV_MOVEAWAY:-}" = '1' ] && [ "${pkg}" != "${pkgori}" ]; then
      mv -n "${pkgori}" "${pkg}"
    fi
  fi
}

build_single_target() {
  export _CPU="$1"

  [ "${_CPU}" = 'a64' ] && return

  _TRIPLET=''
  _SYSROOT=''

  export _CCPREFIX=
  export _MAKE='make'
  export _WINE=''

  # GCC-specific machine selection option
  [ "${_CPU}" = 'x86' ] && _OPTM='-m32'
  [ "${_CPU}" = 'x64' ] && _OPTM='-m64'
  [ "${_CPU}" = 'a64' ] && _OPTM='-m..'  # TODO

  [ "${_CPU}" = 'x86' ] && _machine='i686'
  [ "${_CPU}" = 'x64' ] && _machine='x86_64'
  [ "${_CPU}" = 'a64' ] && _machine='aarch64'

  export _PKGSUFFIX
  [ "${_CPU}" = 'x86' ] && _PKGSUFFIX='-win32-mingw'  # TODO: -> '-win-x86-mingw'
  [ "${_CPU}" = 'x64' ] && _PKGSUFFIX='-win64-mingw'  # TODO: -> '-win-x64-mingw'
  [ "${_CPU}" = 'a64' ] && _PKGSUFFIX='-win-a64-mingw'

  if [ "${_OS}" = 'win' ]; then
    export PATH
    [ "${_CPU}" = 'x86' ] && PATH="/mingw32/bin:${_ori_path}"
    [ "${_CPU}" = 'x64' ] && PATH="/mingw64/bin:${_ori_path}"
    [ "${_CPU}" = 'a64' ] && PATH="/clangarm64/bin:${_ori_path}"
    _MAKE='mingw32-make'

    # Install required component
    pip3 --version
    pip3 --disable-pip-version-check --no-cache-dir install --user "pefile==${PEFILE_VER_}"
  else
    if [ "${_CC}" = 'clang' ] && [ "${_OS}" = 'mac' ]; then
      export PATH="/usr/local/opt/llvm/bin:${_ori_path}"
    fi
    _TRIPLET="${_machine}-w64-mingw32"
    # Prefixes do not work with MSYS2/mingw-w64, because `ar`, `nm` and
    # `runlib` are missing from them. They are accessible either _without_
    # one, or as prefix + `gcc-ar`, `gcc-nm`, `gcc-runlib`.
    _CCPREFIX="${_TRIPLET}-"
    # mingw-w64 sysroots
    if [ "${_OS}" = 'mac' ]; then
      _SYSROOT="/usr/local/opt/mingw-w64/toolchain-${_machine}"
    else
      _SYSROOT="/usr/${_TRIPLET}"
    fi

    # TODO: Run arm64 targets on arm64 linux/mac hosts?
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
      _WINE='wine'  # TODO: What targets can an arm64 host run? Can an x64 host run arm64 targets?
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
      "${_CCPREFIX}gcc" -dumpspecs | sed 's|-lmsvcrt|-lucrt|g' > "${_GCCSPECS}"
    fi
  fi

  # Setup common toolchain configuration options

  export _TOP; _TOP="$(pwd)"  # Must be an absolute path
  export _PKGDIR="${_CPU}-${_CRT}"
  _PREFIX='/usr'
  export _PP="${_PKGDIR}${_PREFIX}"
  export _BLDDIR='bld'
  export _CC_GLOBAL=''
  export _CFLAGS_GLOBAL='-fno-ident'
  export _CPPFLAGS_GLOBAL=''
  export _CXXFLAGS_GLOBAL=''
  export _RCFLAGS_GLOBAL=''
  export _LDFLAGS_GLOBAL=''
  export _LIBS_GLOBAL=''
  export _CONFIGURE_GLOBAL=''
  export _CMAKE_GLOBAL='-Wno-dev -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release'
  export _CMAKE_CXX_GLOBAL=''
  export _LD='ld'  # ld or lld
  export _STRIP="${_CCPREFIX}strip"
  export _OBJDUMP="${_CCPREFIX}objdump"

  # for CMake and openssl
  unset CC

  # for autotools (and openssl)
  export RC="${_CCPREFIX}windres"
  export AR="${_CCPREFIX}ar"
  export NM="${_CCPREFIX}nm"
  export RANLIB="${_CCPREFIX}ranlib"

  # for cmake-autotools.sh
  [ "${_CPU}" = 'x86' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=pe-i386"
  [ "${_CPU}" = 'x64' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=pe-x86-64"
# [ "${_CPU}" = 'a64' ] && _RCFLAGS_GLOBAL="${_RCFLAGS_GLOBAL} --target=..."  # TODO

  if [ "${_OS}" = 'win' ]; then
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -GMSYS Makefiles"
    # Without this, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  elif [ "${_OS}" = 'mac' ]; then
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
  fi

  _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_INSTALL_MESSAGE=NEVER"
  _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_INSTALL_PREFIX=${_PREFIX}"
  _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"

  if [ "${_CRT}" = 'ucrt' ]; then
    if [ "${_CC}" = 'clang' ]; then
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -fuse-ld=lld -Wl,-s"
      _LD='lld'
    else
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -specs=${_GCCSPECS}"
    fi
    _CPPFLAGS_GLOBAL="${_CPPFLAGS_GLOBAL} -D_UCRT"
    _LIBS_GLOBAL="${_LIBS_GLOBAL} -lucrt"
  fi

  [ "${_OS}" != 'win' ] && _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --build=${_CROSS_HOST} --host=${_TRIPLET}"
  [ "${_CPU}" = 'x86' ] && _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -fno-asynchronous-unwind-tables"

  if [ "${_CC}" = 'clang' ]; then
    _CC_GLOBAL="clang${CW_CCSUFFIX} --target=${_TRIPLET}"
    _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} --target=${_TRIPLET}"  # Seems necessary for CMake to recognize clang++
    if [ "${_OS}" != 'win' ]; then
      _CC_GLOBAL="${_CC_GLOBAL} --sysroot=${_SYSROOT}"
      _CXXFLAGS_GLOBAL="${_CXXFLAGS_GLOBAL} --sysroot=${_SYSROOT}"
      _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
    fi
    if [ "${_OS}" = 'linux' ]; then
      # We used to pass this via CFLAGS for CMake to make it detect clang, so
      # we need to pass this via CMAKE_C_FLAGS, though meant for the linker.
      _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
    fi

    # This does not work yet, due to:
    #   /usr/local/bin/x86_64-w64-mingw32-ld: asyn-thread.o:asyn-thread.c:(.rdata$.refptr.__guard_dispatch_icall_fptr[.refptr.__guard_dispatch_icall_fptr]+0x0): undefined reference to `__guard_dispatch_icall_fptr'
  # _CFLAGS_GLOBAL="${_CFLAGS_GLOBAL} -Xclang -cfguard"
  # _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -Xlinker -guard:cf"

    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_SYSROOT=${_SYSROOT}"
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}"
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER_TARGET=${_TRIPLET}"
    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER=clang${CW_CCSUFFIX}"
    _CMAKE_CXX_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}"
    _CMAKE_CXX_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_CXX_COMPILER=clang++${CW_CCSUFFIX}"
  else
    _CC_GLOBAL="${_CCPREFIX}gcc -static-libgcc"
    _LDFLAGS_GLOBAL="${_OPTM} ${_LDFLAGS_GLOBAL}"
    _CFLAGS_GLOBAL="${_OPTM} ${_CFLAGS_GLOBAL}"

    _CMAKE_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_C_COMPILER=${_CCPREFIX}gcc"
    _CMAKE_CXX_GLOBAL="${_CMAKE_GLOBAL} -DCMAKE_CXX_COMPILER=${_CCPREFIX}g++"
  fi

  _LDFLAGS_GLOBAL="${_LDFLAGS_GLOBAL} -static-libgcc"

  _CONFIGURE_GLOBAL="${_CONFIGURE_GLOBAL} --prefix=${_PREFIX} --disable-dependency-tracking --disable-silent-rules"

  # Unified, per-target package: Initialize
  export _UNIPKG="curl-${CURL_VER_}${_REVSUFFIX}${_PKGSUFFIX}${_FLAV}"
  rm -r -f "${_UNIPKG:?}"
  mkdir -p "${_UNIPKG}"
  export _UNIMFT="${_UNIPKG}/BUILD-MANIFEST.txt"

  gccver=''
  [ "${_CC}" = 'clang' ] || gccver="gcc $("${_CCPREFIX}gcc" -dumpversion)"
  binver="binutils $("${_CCPREFIX}ar" V | grep -o -a -E '[0-9]+\.[0-9]+(\.[0-9]+)?')"

  {
    [ -n "${clangver}" ] && echo ".${clangver}"
    [ -n "${gccver}" ]   && echo ".${gccver}"
    [ -n "${mingwver}" ] && echo ".${mingwver}"
    echo ".${binver}"
  } >> "${_BLD}"

  {
    [ -n "${clangver}" ] && echo ".${clangver}"
    [ -n "${gccver}" ]   && echo ".${gccver}"
    [ -n "${mingwver}" ] && echo ".${mingwver}"
    echo ".${binver}"
  } >> "${_UNIMFT}"

  bld zlib             "${ZLIB_VER_}"
  bld brotli         "${BROTLI_VER_}"
  bld libidn2       "${LIBIDN2_VER_}"
  bld libgsasl     "${LIBGSASL_VER_}"
  bld nghttp2       "${NGHTTP2_VER_}"
  bld nghttp3       "${NGHTTP3_VER_}"
  bld libressl     "${LIBRESSL_VER_}"
  bld openssl       "${OPENSSL_VER_}"
  bld openssl  "${OPENSSL_QUIC_VER_}" openssl-quic
  bld ngtcp2         "${NGTCP2_VER_}"
  bld libssh2       "${LIBSSH2_VER_}"
  bld curl             "${CURL_VER_}"

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
          openssl dgst -sha512 "${f}"
        done
      } > "${_fn}"
      touch -c -r "../${_ref}" "${_fn}"
    )

    _fn="${_DST}/BUILD-README.txt"
    cat <<EOF > "${_fn}"
Visit the project page for details about these builds and the list of changes:

  ${_URL}
EOF
    touch -c -r "${_ref}" "${_fn}"

    _fn="${_DST}/BUILD-HOMEPAGE.url"
    cat <<EOF > "${_fn}"
[InternetShortcut]
URL=${_URL}
EOF
    unix2dos --quiet --keepdate "${_fn}"
    touch -c -r "${_ref}" "${_fn}"

    if [ -n "${_LOGURL}" ]; then  # Link to the build log
      _fn="${_DST}/BUILD-LOG.url"
      cat <<EOF > "${_fn}"
[InternetShortcut]
URL=${_LOGURL}
EOF
      unix2dos --quiet --keepdate "${_fn}"
      touch -c -r "${_ref}" "${_fn}"
    fi

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
