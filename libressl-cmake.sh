#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
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

  rm -r -f pkg CMakeFiles CMakeCache.txt CTestTestfile.cmake cmake_install.cmake

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  _CFLAGS="${_OPTM} -fno-ident -ffile-prefix-map=$(pwd)="
  [ "${_CRT}" = 'ucrt' ] && _CFLAGS="${_CFLAGS} -D_UCRT"
  [ "${_CPU}" = 'x86' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  [ "${_OS}" = 'mac' ] && options="${options} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
  options="${options} -DLIBRESSL_TESTS=OFF"
  options="${options} -DLIBRESSL_APPS=OFF"
  options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
  options="${options} -DCMAKE_RC_FLAGS=-DGCC_WINDRES"
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"

  if [ "${_CC}" = 'clang' ]; then
    unset CC

    [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

  # _CFLAGS="${_CFLAGS} -Xclang -cfguard"

    # shellcheck disable=SC2086
    cmake . ${options} ${opt_gmsys} \
      "-DCMAKE_SYSROOT=${_SYSROOT}" \
      "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${CW_CCSUFFIX}" \
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

  # Build fixups for CMake

  # CMake creates static libs with version numbers in them,
  # e.g. libcrypto-49.a. Strangely the .pc files do not have
  # them.
  # Strip those to make them findable by other projects.
  for l in libcrypto libssl libtls; do
    mv "${_pkg}/lib/${l}"*.a "${_pkg}/lib/${l}.a"
  done

  # Delete .pc files
  rm -r -f ${_pkg}/lib/pkgconfig

  # List files created

  find "${_pkg}" | grep -a -v -F '/share/' | sort

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ${_pkg}/include/openssl/*.h
  touch -c -r "${_ref}" ${_pkg}/include/*.h

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p ${_pkg}/lib/*.a             "${_DST}/lib"
  cp -f -p ${_pkg}/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p ${_pkg}/include/*.h         "${_DST}/include/"
  cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
  cp -f -p COPYING                     "${_DST}/COPYING.txt"
  cp -f -p README.md                   "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
