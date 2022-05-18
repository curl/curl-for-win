#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  [ "${_OS}" != 'win' ] && options="--build=${_CROSS_HOST} --host=${_TRIPLET}"

  # Build

  rm -r -f pkg

  find . -name '*.o'   -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete
  find . -name '*.dll' -delete
  find . -name '*.exe' -delete

  export LDFLAGS="${_OPTM}"
  export CPPFLAGS=''
  ldonly=''

  if [ "${CC}" = 'mingw-clang' ]; then
    export CC='clang'
    if [ "${_OS}" != 'win' ]; then
      options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
      LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
      [ "${_OS}" = 'linux' ] && ldonly="${ldonly} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
    fi
    export AR="${_CCPREFIX}ar"
    export NM="${_CCPREFIX}nm"
    export RANLIB="${_CCPREFIX}ranlib"
    export CFLAGS="${LDFLAGS} -Wno-inconsistent-dllimport"
  else
    export CC="${_CCPREFIX}gcc -static-libgcc"
    export CFLAGS="${LDFLAGS} -Wno-attributes"
  fi

  CFLAGS="${CFLAGS} -fno-ident"
  LDFLAGS="${LDFLAGS}${ldonly}"
  [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"
  [ "${_CPU}" = 'x86' ] && CPPFLAGS="${CPPFLAGS} -D__MINGW_USE_VC2005_COMPAT"

  _prefix='C:/Windows/libressl'
  _ssldir="ssl"
  _pkr='pkg'

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-tests \
    --silent \
    "--prefix=${_prefix}" \
    "--with-openssldir=${_prefix}/${_ssldir}"
# make clean > /dev/null
  # Install it so that it can be detected by CMake
  # (ending slash required)
  make --jobs 2 install "DESTDIR=$(pwd)/${_pkr}/" >/dev/null # 2>&1

  # DESTDIR= + --prefix=
  # LibreSSL and OpenSSL 3.x does not strip the drive letter
  # (openssl/pkg/C:/Windows/libressl)
  _pkg="${_pkr}/${_prefix}"
  _pks="${_pkr}/${_prefix}/${_ssldir}"

  # Build fixups for clang

  # 'configure' misdetects CC=clang as MSVC and then uses '.lib'
  # extension. Rename these to '.a':
  for l in libcrypto libssl libtls; do
    if [ -f "${_pkg}/lib/${l}.lib" ]; then
      sed -i.bak "s|\.lib'$|.a'|g" "${_pkg}/lib/${l}.la"
      mv "${_pkg}/lib/${l}.lib" "${_pkg}/lib/${l}.a"
    fi
  done

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/lib/*.a
  touch -c -r "${_ref}" "${_pkg}"/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" "${_pkg}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_pkg}"/include/*.h

  # Tests

  for bin in \
    "${_pkg}"/bin/openssl.exe \
  ; do
    file "${bin}"
    # Produce 'openssl version -a'-like output without executing the build:
    strings "${bin}" | grep -a -E '^(LibreSSL [0-9]|built on: |compiler: |platform: |[A-Z]+DIR: )' || true
  done

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib"
  cp -f -p "${_pkg}"/lib/pkgconfig/*.pc  "${_DST}/lib/pkgconfig/"
  cp -f -p "${_pkg}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_pkg}"/include/*.h         "${_DST}/include/"
  cp -f -p ChangeLog                     "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                       "${_DST}/COPYING.txt"
  cp -f -p README.md                     "${_DST}/"

  # Copy libs to an OpenSSL-compatible location so that libssh2 and curl find them.
  cp -f -p "${_pkg}"/lib/*.a ./

  ../_pkg.sh "$(pwd)/${_ref}"
)
