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
_cpu="$2"

(
  cd "${_NAM}" || exit

  if [ "${_OS}" != 'win' ]; then

    # https://clang.llvm.org/docs/CrossCompilation.html
    unset _HOST
    case "${_OS}" in
      win)   _HOST='x86_64-pc-mingw32';;
      linux) _HOST='x86_64-pc-linux';;  # x86_64-pc-linux-gnu
      mac)   _HOST='x86_64-apple-darwin';;
      bsd)   _HOST='x86_64-pc-bsd';;
    esac

    options="--build=${_HOST} --host=${_TRIPLET}"
  fi

  # Build

  rm -r -f pkg

  export LDFLAGS="-m${_cpu}"

  # No success in convincing the build system to work correctly with clang:
  if [ "${CC}" = 'mingw-clang' ]; then

    # Skip 'gltests' build due to errors like this:
    #   ./signal.h:922:3: error: unknown type name 'uid_t'; did you mean 'pid_t'?
    sed -i.bak -E 's| gltests||g' ./Makefile.am

    export CC='clang'
    if [ "${os}" != 'win' ]; then
      export options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
      LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
      [ "${os}" = 'linux' ] && options="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${options}"
    fi
    export AR=${_CCPREFIX}ar
    export NM=${_CCPREFIX}nm
    export RANLIB=${_CCPREFIX}ranlib
    export RC=${_CCPREFIX}windres
  else
    export CC="${_CCPREFIX}gcc -static-libgcc"
  fi

  export CFLAGS="${LDFLAGS} -fno-ident"
  [ "${_cpu}" = '32' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"
  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-rpath \
    --enable-static \
    --disable-shared \
    --enable-scram-sha1 \
    --enable-scram-sha256 \
    --disable-obsolete \
    --disable-valgrind-tests \
    '--prefix=/usr/local' \
    --silent
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Build fixups for clang

  # libgsasl configure misdetects CC=clang as MSVC and then uses '.lib'
  # extension. So rename these to '.a':
  if [ -f "${_pkg}/lib/libgsasl.lib" ]; then
    sed -i.bak -E "s|\.lib'$|.a'|g" "${_pkg}/lib/libgsasl.la"
    mv "${_pkg}/lib/libgsasl.lib" "${_pkg}/lib/libgsasl.a"
  fi

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/include/*.h

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}-win${_cpu}-mingw"
  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/include/*.h        "${_DST}/include/"
  cp -f -p NEWS                       "${_DST}/NEWS.txt"
  cp -f -p AUTHORS                    "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README                     "${_DST}/README.txt"

  unix2dos --quiet --keepdate "${_DST}"/*.txt

  ../_pkg.sh "$(pwd)/${_ref}"
)
