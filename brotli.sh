#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
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
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  _CFLAGS="${_OPTM} -fno-ident -DMINGW_HAS_SECURE_API"
  [ "${_CRT}" = 'ucrt' ] && _CFLAGS="${_CFLAGS} -D_UCRT"
  [ "${_CPU}" = 'x86' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  [ "${_OS}" = 'mac' ] && options="${options} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"
  options="${options} -DBROTLI_DISABLE_TESTS=ON"

  if [ "${CC}" = 'mingw-clang' ]; then
    unset CC

    [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

  # _CFLAGS="${_CFLAGS} -Xclang -cfguard"

    # shellcheck disable=SC2086
    cmake . ${options} ${opt_gmsys} \
      "-DCMAKE_SYSROOT=${_SYSROOT}" \
      "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
      "-DCMAKE_CXX_COMPILER=clang++${_CCSUFFIX}" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} ${opt_gmsys} \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_CXX_COMPILER=${_CCPREFIX}g++" \
      "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}"
  fi

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  # Remove '-static' suffixes from static lib names to make these behave
  # like most other projects do. And, also to be in sync with the .pc
  # files that are correctly generated in the same CMake build process.

  for fn in "${_pkg}"/lib/*-static.a; do
    mv "${fn}" "$(echo "${fn}" | sed 's|-static||')"
  done

  # Delete implibs

  rm -f ${_pkg}/lib/*.dll.a

  # libcurl only uses the decoding functionality

  rm -f ${_pkg}/lib/libbrotlienc.a
  rm -f ${_pkg}/lib/pkgconfig/libbrotlienc.pc

  # Make steps for determinism

  readonly _ref='docs/brotli.1'

  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/include/brotli/*.h
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"
  mkdir -p "${_DST}/lib/pkgconfig"
  mkdir -p "${_DST}/include/brotli"

  cp -f -p ${_pkg}/include/brotli/*.h "${_DST}/include/brotli/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p README.md                  "${_DST}/"
  cp -f -p LICENSE                    "${_DST}/LICENSE.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
