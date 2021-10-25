#!/bin/sh

# Copyright 2017-present Viktor Szakats. See LICENSE.md

set -euxo pipefail

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

  cd build/cmake

  rm -r -f pkg CMakeFiles CMakeCache.txt cmake_install.cmake lib/CMakeFiles

  find . -name 'Makefile'              -delete
  find . -name 'cmake_install.cmake'   -delete
  find . -name 'cmake_uninstall.cmake' -delete
  find . -name '*.dll'                 -delete
  find . -name '*.o'                   -delete
  find . -name '*.obj'                 -delete
  find . -name '*.a'                   -delete
  find . -name '*.lo'                  -delete
  find . -name '*.la'                  -delete
  find . -name '*.lai'                 -delete
  find . -name '*.Plo'                 -delete
  find . -name '*.pc'                  -delete

  # -D_LARGEFILE64_SOURCE=1 -D_LFS64_LARGEFILE=1
  _CFLAGS="${_OPTM} -fno-ident -target ${_TRIPLET}"
  [ "${_CPU}" = 'x86' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"
  _LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
  [ "${_CPU}" = 'x64' ] && _LDFLAGS="${_LDFLAGS} -Wl,--high-entropy-va -Wl,--image-base,0x153000000"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE:STRING=Release"
  # A bizarre fix that became required around year 2021 to not fail instantly
  # on macOS when using clang. Likely not the correct/complete fix.
  [ "${_OS}" = 'mac' ] && options="${options} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
  options="${options} -DCMAKE_EXECUTABLE_FORMAT:STRING=PE"
  options="${options} -DZSTD_BUILD_CONTRIB:BOOL=OFF"
  options="${options} -DZSTD_BUILD_TESTS:BOOL=OFF"
  options="${options} -DZSTD_LEGACY_SUPPORT:BOOL=OFF"
  # Not required for curl itself, but doesn't take much extra time, so let's build it
  options="${options} -DZSTD_BUILD_PROGRAMS:BOOL=ON"
  options="${options} -DZSTD_PROGRAMS_LINK_SHARED:BOOL=ON"
  options="${options} -DZSTD_BUILD_SHARED:BOOL=ON"
  options="${options} -DZSTD_BUILD_STATIC:BOOL=ON"
  options="${options} -DZSTD_MULTITHREAD_SUPPORT:BOOL=OFF"
  options="${options} -DZSTD_LZ4_SUPPORT:BOOL=OFF"
  options="${options} -DZSTD_LZMA_SUPPORT:BOOL=OFF"
  options="${options} -DZSTD_ZLIB_SUPPORT:BOOL=OFF"
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
      "-DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
      "-DCMAKE_CXX_COMPILER=clang++${_CCSUFFIX}" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}" \
      "-DCMAKE_CXX_FLAGS=${_CFLAGS}" \
      '-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc' \
      "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_CXX_COMPILER=${_CCPREFIX}g++" \
      "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}" \
      "-DCMAKE_CXX_FLAGS=${_CFLAGS}" \
      "-DCMAKE_SHARED_LINKER_FLAGS=${_LDFLAGS}"
  fi

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  cd ../..

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='build/cmake/pkg/usr/local'

  ls -l ${_pkg}/bin/*.exe
  ls -l ${_pkg}/lib/*.a
  ls -l ${_pkg}/../../../lib/*.dll

  # libssh2 and curl makefile.m32 assume the headers and lib to be in the
  # same directory. Make sure to copy the static library only:
# cp -f -p ${_pkg}/include/*.h   "${_pkg}/"
# cp -f -p ${_pkg}/lib/libzstd.a "${_pkg}/"

  # Make steps for determinism

  readonly _ref='CHANGELOG'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.exe
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/../../../lib/*.dll

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.exe
  ../_peclean.py "${_ref}" ${_pkg}/../../../lib/*.dll

  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.exe
  ../_sign-code.sh "${_ref}" ${_pkg}/../../../lib/*.dll

  touch -c -r "${_ref}" ${_pkg}/include/*.h
  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/../../../lib/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Tests

  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.exe          | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers ${_pkg}/../../../lib/*.dll | grep -a -E -i "(file format|dll name)"

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"

  mkdir -p "${_DST}/bin"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  cp -f -p ${_pkg}/include/*.h        "${_DST}/include/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p ${_pkg}/bin/*.exe          "${_DST}/bin/"
  cp -f -p ${_pkg}/../../../lib/*.dll "${_DST}/bin/"
  cp -f -p CHANGELOG                  "${_DST}/CHANGELOG.txt"
  cp -f -p README.md                  "${_DST}/"
  cp -f -p LICENSE                    "${_DST}/LICENSE.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
