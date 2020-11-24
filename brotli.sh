#!/bin/sh -ex

# Copyright 2017-present Viktor Szakats <https://vsz.me/>
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
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete

  _CFLAGS="-m${_cpu} -fno-ident -DMINGW_HAS_SECURE_API"
  [ "${_cpu}" = '32' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"

  options=''
  options="${options} -DCMAKE_SYSTEM_NAME=Windows"
  options="${options} -DCMAKE_BUILD_TYPE=Release"
  options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
  options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

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
      "-DCMAKE_CXX_COMPILER_TARGET=${_TRIPLET}" \
      "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
      "-DCMAKE_CXX_COMPILER=clang++${_CCSUFFIX}" \
      "-DCMAKE_C_FLAGS=${_CFLAGS}" \
      "-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}" \
      "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}"
  else
    unset CC

    # shellcheck disable=SC2086
    cmake . ${options} "${opt_gmsys}" \
      "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
      "-DCMAKE_CXX_COMPILER=${_CCPREFIX}g++" \
      "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}"
  fi

  make --jobs 2 install "DESTDIR=$(pwd)/pkg"

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  # Remove '-static' suffixes from static lib names to make these behave
  # like other most other projects do.

# for fn in ${_pkg}/lib/*-static.a; do mv "${fn}" "$(echo "${fn}" | sed 's|-static||')"; done

  # Make steps for determinism

  readonly _ref='docs/brotli.1'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.exe
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.dll

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.exe
  ../_peclean.py "${_ref}" ${_pkg}/bin/*.dll

  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.exe
  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.dll

  touch -c -r "${_ref}" ${_pkg}/include/brotli/*.h
  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/bin/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Tests

  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.dll | grep -a -E -i "(file format|dll name)"

  # Create package

  _BAS="${_NAM}-${_VER}${_REV}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"
  mkdir -p "${_DST}/bin"
  mkdir -p "${_DST}/lib/pkgconfig"
  mkdir -p "${_DST}/include/brotli"

  cp -f -p ${_pkg}/include/brotli/*.h "${_DST}/include/brotli/"
  cp -f -p ${_pkg}/bin/*.exe          "${_DST}/bin/"
  cp -f -p ${_pkg}/bin/*.dll          "${_DST}/bin/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p README.md                  "${_DST}/"
  cp -f -p LICENSE                    "${_DST}/LICENSE.txt"

  unix2dos --quiet --keepdate "${_DST}"/*.md
  unix2dos --quiet --keepdate "${_DST}"/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
)
