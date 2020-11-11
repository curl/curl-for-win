#!/bin/sh -ex

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.' | cut -f 1 -d '_')"
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

  rm -r -f pkg

  find . -name '*.a'  -delete
  find . -name '*.pc' -delete

  for pass in 'static' 'shared'; do

    rm -r -f CMakeFiles CMakeCache.txt cmake_install.cmake

    find . -name '*.o'   -delete
    find . -name '*.obj' -delete
    find . -name '*.lo'  -delete
    find . -name '*.la'  -delete
    find . -name '*.lai' -delete
    find . -name '*.Plo' -delete

    _CFLAGS="-m${_cpu} -fno-ident"
    [ "${_cpu}" = '32' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"
    _LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
    [ "${_cpu}" = '64' ] && _LDFLAGS="${_LDFLAGS} -Wl,--high-entropy-va -Wl,--image-base,0x152000000"
    if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
      _LDFLAGS="${_LDFLAGS} -Wl,-Map,libssh2.map"
    fi

    options=''
    options="${options} -DCMAKE_SYSTEM_NAME=Windows"
    options="${options} -DCMAKE_BUILD_TYPE=Release"
    [ "${pass}" = 'static' ] && options="${options} -DBUILD_SHARED_LIBS=0"
    [ "${pass}" = 'shared' ] && options="${options} -DBUILD_SHARED_LIBS=1"
    options="${options} -DBUILD_EXAMPLES=0"
    options="${options} -DBUILD_TESTING=0"
    options="${options} -DENABLE_ZLIB_COMPRESSION=1"
    options="${options} -DZLIB_INCLUDE_DIR:PATH=$(pwd)/../zlib/pkg/usr/local/include"
    options="${options} -DZLIB_LIBRARY:FILEPATH=$(pwd)/../zlib/pkg/usr/local/lib/libz.a"
    options="${options} -DCRYPTO_BACKEND=OpenSSL"
    options="${options} -DOPENSSL_ROOT_DIR=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/"
    options="${options} -DOPENSSL_INCLUDE_DIR=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/include"
    options="${options} -DOPENSSL_LIBRARIES=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/lib"
    options="${options} -DOPENSSL_CRYPTO_LIBRARY=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/lib"
    options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
    options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
    options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

    # https://cmake.org/cmake/help/v3.11/manual/cmake-properties.7.html#properties-on-targets
    [ "${pass}" = 'shared' ] && [ "${_cpu}" = '64' ] && options="${options} -DCMAKE_RELEASE_POSTFIX=-x64"

    if [ "${CC}" = 'mingw-clang' ]; then
      unset CC

      [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

      # '-DMINGW=1' required to detect OpenSSL

      # shellcheck disable=SC2086
      cmake . ${options} "${opt_gmsys}" \
        "-DMINGW=1" \
        "-DCMAKE_SYSROOT=${_SYSROOT}" \
        "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
        "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
        "-DCMAKE_C_COMPILER=clang${_CCSUFFIX}" \
        "-DCMAKE_C_FLAGS=${_CFLAGS}" \
        "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc ${_LDFLAGS}"
    else
      unset CC

      # shellcheck disable=SC2086
      cmake . ${options} "${opt_gmsys}" \
        "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
        "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}" \
        "-DCMAKE_SHARED_LINKER_FLAGS=${_LDFLAGS}"
    fi

    make --jobs 2 install "DESTDIR=$(pwd)/pkg"  # VERBOSE=1
  done

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  ls -l ${_pkg}/bin/*.dll
  ls -l ${_pkg}/lib/*.a

  # Stick to the name used by GNU Make builds
  [ "${_cpu}" = '32' ] && mv -f ${_pkg}/lib/liblibssh2.dll.a     ${_pkg}/lib/libssh2.dll.a
  [ "${_cpu}" = '64' ] && mv -f ${_pkg}/lib/liblibssh2-x64.dll.a ${_pkg}/lib/libssh2.dll.a

  # curl makefile.m32 assumes a certain layout.
  # Also make sure to copy the static library only:
  mkdir -p "${_pkg}/win32/"
  cp -f -p ${_pkg}/lib/libssh2.a "${_pkg}/win32/"

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.dll

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.dll

  ../_signcode.sh "${_ref}" ${_pkg}/bin/*.dll

  touch -c -r "${_ref}" ${_pkg}/bin/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" ${_pkg}/bin/*.map
    touch -c -r "${_ref}" ${_pkg}/bin/*.def || true
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.dll | grep -a -E -i "(file format|dll name)"

  # Create package

  _BAS="${_NAM}-${_VER}${_REV}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/bin"
  mkdir -p "${_DST}/lib"
  mkdir -p "${_DST}/lib/pkgconfig"
  mkdir -p "${_DST}/include"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && [ "${file}" != 'Makefile' ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p ${_pkg}/include/*.h        "${_DST}/include/"
  cp -f -p ${_pkg}/bin/*.dll          "${_DST}/bin/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p NEWS                       "${_DST}/NEWS.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README                     "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES              "${_DST}/RELEASE-NOTES.txt"

  # OpenSSL 3.x
  [ -d ../openssl ] && [ -f ../openssl/LICENSE.txt ] && cp -f -p ../openssl/LICENSE.txt "${_DST}/COPYING-openssl.txt"
  # OpenSSL 1.x
  [ -d ../openssl ] && [ -f ../openssl/LICENSE     ] && cp -f -p ../openssl/LICENSE     "${_DST}/COPYING-openssl.txt"

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    cp -f -p ${_pkg}/bin/*.map   "${_DST}/bin/"
    cp -f -p ${_pkg}/bin/*.def   "${_DST}/bin/" || true
  fi

  unix2dos --quiet --keepdate "${_DST}"/*.txt
  unix2dos --quiet --keepdate "${_DST}"/docs/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
)
