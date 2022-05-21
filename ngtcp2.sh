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

  # Cross-tasks

  if [ "${_OS}" = 'win' ]; then
    opt_gmsys='-GMSYS Makefiles'
    # Without this option, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  else
    opt_gmsys=''
  fi

  # Build

  rm -r -f pkg CMakeFiles CMakeCache.txt ./*.cmake

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  _CFLAGS="${_OPTM} -fno-ident -DNDEBUG"
  [ "${_CPU}" = 'x86' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  # A bizarre fix that became required around year 2021 to not fail instantly
  # on macOS when using clang. Likely not the correct/complete fix.
  [ "${_OS}" = 'mac' ] && options="${options} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
  options="${options} -DENABLE_STATIC_LIB=1"
  options="${options} -DENABLE_SHARED_LIB=0"
  if [ -d ../openssl_quic ]; then
    options="${options} -DENABLE_OPENSSL=1"
    options="${options} -DHAVE_SSL_IS_QUIC=1"  # Detection fails with a long list of unfixable errors, so force it.
    options="${options} -DOPENSSL_ROOT_DIR=../openssl_quic/pkg/usr/local"
    options="${options} -DOPENSSL_INCLUDE_DIR=../openssl_quic/pkg/usr/local/include"
  fi
  if [ -d ../nghttp3 ]; then
    options="${options} -DLIBNGHTTP3_LIBRARY=../nghttp3/pkg/usr/local/lib"
    options="${options} -DLIBNGHTTP3_INCLUDE_DIR=../nghttp3/pkg/usr/local/include"
  fi
  options="${options} -DLIBEV_LIBRARY="  # To avoid finding any non-cross copies
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"
  # We do not need C++ with ENABLE_LIB_ONLY, so make sure to skip the
  # detection logic and all the potential detection issues with it.
  options="${options} -DCMAKE_CXX_COMPILER_WORKS=1"

  if [ "${CC}" = 'mingw-clang' ]; then
    unset CC

    [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

  # _CFLAGS="${_CFLAGS} -Xclang -cfguard"

    # shellcheck disable=SC2086
    cmake . ${options} ${opt_gmsys} \
      "-DCMAKE_SYSROOT=${_SYSROOT}" \
      "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} ${opt_gmsys} \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}"
  fi

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  # Rename static libs so they get found by dependents

  if [ -d ../openssl_quic ]; then
    mv -f ${_pkg}/lib/libngtcp2_crypto_openssl_static.a ${_pkg}/lib/libngtcp2_crypto_openssl.a
  fi
  mv -f ${_pkg}/lib/libngtcp2_static.a ${_pkg}/lib/libngtcp2.a

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/include/ngtcp2/*.h
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/ngtcp2"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/include/ngtcp2/*.h "${_DST}/include/ngtcp2/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p ChangeLog                  "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                    "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README.rst                 "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
