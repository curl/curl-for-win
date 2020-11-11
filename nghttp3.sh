#!/bin/sh -ex

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
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

  if [ "${_OS}" = 'win' ]; then
    opt_gmsys='-GMSYS Makefiles'
    # Without this option, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  fi

  # Build

  rm -r -f pkg CMakeFiles CMakeCache.txt cmake_install.cmake

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  _CFLAGS="-m${_cpu} -fno-ident -DNDEBUG"
  [ "${_cpu}" = '32' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  options="${options} -DENABLE_LIB_ONLY=1"
  options="${options} -DENABLE_STATIC_LIB=1"
  options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"
  # We don't need C++ with ENABLE_LIB_ONLY, so make sure to skip the
  # detection logic and all the potential detection issues with it.
  options="${options} -DCMAKE_CXX_COMPILER_WORKS=1"

  if [ "${CC}" = 'mingw-clang' ]; then
    unset CC

    [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

    _LDFLAGS=''
  # _CFLAGS="${_CFLAGS} -Xclang -cfguard"
  # _LDFLAGS="${_LDFLAGS} -Xlinker -guard:cf"

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_SYSROOT=${_SYSROOT}" \
      "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}" \
      "-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}" \
      "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}"
  fi

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  # Delete the implib, we need the static lib only
  rm -f ${_pkg}/lib/*.dll.a

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/include/nghttp3/*.h
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Create package

  _BAS="${_NAM}-${_VER}${_REV}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/nghttp3"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/include/nghttp3/*.h "${_DST}/include/nghttp3/"
  cp -f -p ${_pkg}/lib/*.a             "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc  "${_DST}/lib/pkgconfig/"
  cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                     "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                     "${_DST}/COPYING.txt"
  cp -f -p README.rst                  "${_DST}/"

  unix2dos --quiet --keepdate "${_DST}"/*.txt
  unix2dos --quiet --keepdate "${_DST}"/*.rst

  ../_pack.sh "$(pwd)/${_ref}"
)
