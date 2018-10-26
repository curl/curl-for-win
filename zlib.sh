#!/bin/sh -ex

# Copyright 2017-2018 Viktor Szakats <https://vszakats.net/>
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

  rm -fr pkg CMakeFiles CMakeCache.txt cmake_install.cmake

  find . -name '*.o'   -type f -delete
  find . -name '*.obj' -type f -delete
  find . -name '*.a'   -type f -delete
  find . -name '*.lo'  -type f -delete
  find . -name '*.la'  -type f -delete
  find . -name '*.lai' -type f -delete
  find . -name '*.Plo' -type f -delete
  find . -name '*.pc'  -type f -delete

  _CFLAGS="-m${_cpu} -fno-ident -D_LARGEFILE64_SOURCE=1 -D_LFS64_LARGEFILE=1"
  [ "${_cpu}" = '32' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"
  _LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
  [ "${_cpu}" = '64' ] && _LDFLAGS="${_LDFLAGS} -Wl,--high-entropy-va -Wl,--image-base,0x155000000"

  options='-DCMAKE_SYSTEM_NAME=Windows'
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
  options="${options} -DCMAKE_RC_FLAGS=-DGCC_WINDRES"
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

  if [ "${CC}" = 'mingw-clang' ]; then
    unset CC

    [ "${os}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_SYSROOT=${_SYSROOT}" \
      "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}" \
      '-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc' \
      "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}" \
      "-DCMAKE_SHARED_LINKER_FLAGS=${_LDFLAGS}"
  fi

  make install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  ls -l ${_pkg}/bin/*.dll
  ls -l ${_pkg}/lib/*.a

  # Delete the implib, we need the static lib only
  rm -f ${_pkg}/lib/*.dll.a
  # Stick to the name used by win32/Makefile.gcc
  mv -f ${_pkg}/lib/libzlibstatic.a ${_pkg}/lib/libz.a

  # libssh2 and curl makefile.m32 assume the headers and lib to be in the
  # same directory. Make sure to copy the static library only:
  cp -f -p ${_pkg}/include/*.h "${_pkg}/"
  cp -f -p ${_pkg}/lib/libz.a  "${_pkg}/"

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" -p -s ${_pkg}/bin/*.dll

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.dll

  ../_sign.sh "${_ref}" ${_pkg}/bin/*.dll

  touch -c -r "${_ref}" ${_pkg}/include/*.h
  touch -c -r "${_ref}" ${_pkg}/bin/*.dll
# touch -c -r "${_ref}" ${_pkg}/share/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Tests

  "${_CCPREFIX}objdump" -x ${_pkg}/bin/*.dll | grep -E -i "(file format|dll name)"

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"

  cp -f -p ${_pkg}/include/*.h          "${_DST}/"
# cp -f -p ${_pkg}/share/pkgconfig/*.pc "${_DST}/"
  cp -f -p ${_pkg}/lib/*.a              "${_DST}/"
  cp -f -p ChangeLog                    "${_DST}/ChangeLog.txt"
  cp -f -p README                       "${_DST}/README.txt"

  unix2dos -q -k "${_DST}"/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
