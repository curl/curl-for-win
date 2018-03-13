#!/bin/sh -ex

# Copyright 2014-2018 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_cpu="$2"

(
  cd "${_NAM}" || exit

  # Cross-tasks

  # Detect host OS
  case "$(uname)" in
    *_NT*)   os='win';;
    Linux*)  os='linux';;
    Darwin*) os='mac';;
    *BSD)    os='bsd';;
  esac

  if [ "${os}" = 'win' ]; then
    opt_gmsys='-GMSYS Makefiles'
    # Without this option, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  fi

  # Build

  rm -fr CMakeFiles CMakeCache.txt cmake_install.cmake

  find . -name '*.o'   -type f -delete
  find . -name '*.a'   -type f -delete
  find . -name '*.lo'  -type f -delete
  find . -name '*.la'  -type f -delete
  find . -name '*.lai' -type f -delete
  find . -name '*.Plo' -type f -delete
  find . -name '*.pc'  -type f -delete

  _CFLAGS="-m${_cpu} -fno-ident"
  [ "${_cpu}" = '32' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"

  options='-DCMAKE_SYSTEM_NAME=Windows'
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  options="${options} -DENABLE_LIB_ONLY=1"
  options="${options} -DENABLE_STATIC_LIB=1"
  options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

  if [ "${CC}" = '-mingw-clang' ]; then
    unset CC

    [ "${os}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_SYSROOT=${_SYSROOT}" \
      "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang" \
      "-DCMAKE_CXX_COMPILER=clang++" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}" \
      "-DCMAKE_CXX_FLAGS=${_CFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_CXX_COMPILER=${_CCPREFIX}g++" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}" \
      "-DCMAKE_CXX_FLAGS=${_CFLAGS}"
  fi

  make
  make install "DESTDIR=$(pwd)/pkg" > /dev/null

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  # Delete the implib, we need the static lib only
  rm -f ${_pkg}/lib/*.dll.a

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/include/nghttp2/*.h
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/nghttp2"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/include/nghttp2/*.h "${_DST}/include/nghttp2/"
  cp -f -p ${_pkg}/lib/*.a             "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc  "${_DST}/lib/pkgconfig/"
  cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                     "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                     "${_DST}/COPYING.txt"
  cp -f -p README.rst                  "${_DST}/"

  unix2dos -k "${_DST}"/*.txt
  unix2dos -k "${_DST}"/*.rst

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
