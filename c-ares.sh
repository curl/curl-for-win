#!/bin/sh -ex

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

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

  _CFLAGS="${_OPTM} -fno-ident"
  [ "${_CPU}" = '32' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"
  _LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
  [ "${_CPU}" = '64' ] && _LDFLAGS="${_LDFLAGS} -Wl,--high-entropy-va -Wl,--image-base,0x154000000"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  options="${options} -DCARES_STATIC=1"
  options="${options} -DCARES_STATIC_PIC=1"
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

  if [ "${CC}" = 'mingw-clang' ]; then
    unset CC

    [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

  # _CFLAGS="${_CFLAGS} -Xclang -cfguard"
  # _LDFLAGS="${_LDFLAGS} -Xlinker -guard:cf"

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

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  ls -l ${_pkg}/bin/*.exe
  ls -l ${_pkg}/bin/*.dll
  ls -l ${_pkg}/lib/*.a

  # Stick to the name used by GNU Make builds
  mv -f ${_pkg}/lib/libcares_static.a ${_pkg}/lib/libcares.a

  # curl makefile.m32 assumes the headers and lib to be in the same directory.
  # Make sure to copy the static library only:
  cp -f -p ${_pkg}/include/*.h    "${_pkg}/"
  cp -f -p ${_pkg}/lib/libcares.a "${_pkg}/"

  # Make steps for determinism

  readonly _ref='RELEASE-NOTES'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.exe
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.dll

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.exe
  ../_peclean.py "${_ref}" ${_pkg}/bin/*.dll

  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.exe
  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.dll

  touch -c -r "${_ref}" ${_pkg}/include/*.h
  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/bin/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}-win${_CPU}-mingw"
  _BAS="${_NAM}-${_VER}-win${_CPU}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"
  mkdir -p "${_DST}/bin"
  mkdir -p "${_DST}/lib/pkgconfig"
  mkdir -p "${_DST}/include"

  cp -f -p ${_pkg}/include/*.h        "${_DST}/include/"
  cp -f -p ${_pkg}/bin/*.exe          "${_DST}/bin/"
  cp -f -p ${_pkg}/bin/*.dll          "${_DST}/bin/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib"
  cp -f -p README.md                  "${_DST}/"
  cp -f -p CHANGES                    "${_DST}/CHANGES.txt"
  cp -f -p RELEASE-NOTES              "${_DST}/RELEASE-NOTES.txt"
  cp -f -p LICENSE.md                 "${_DST}/"

  unix2dos --quiet --keepdate "${_DST}"/*.md
  unix2dos --quiet --keepdate "${_DST}"/*.txt

# ../_pkg.sh "$(pwd)/${_ref}"
)
