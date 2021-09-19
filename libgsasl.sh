#!/bin/sh -ex

# Copyright 2014-present Viktor Szakats. See LICENSE.md

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

  [ "${_OS}" != 'win' ] && options="--build=${_CROSS_HOST} --host=${_TRIPLET}"

  # Build

  rm -r -f pkg

  # To fix this bizarre error when executing 'make':
  #   configure.ac:39: error: version mismatch.  This is Automake 1.16.4,
  #   configure.ac:39: but the definition used by this AM_INIT_AUTOMAKE
  #   configure.ac:39: comes from Automake 1.16.3.  You should recreate
  #   configure.ac:39: aclocal.m4 with aclocal and run automake again.
  #   [...]
  # Requires: autopoint (sometimes offered by the gettext package)
  [ -f 'Makefile' ] || autoreconf -fi

  export LDFLAGS="${_OPTM}"
  unset ldonly

  # No success in convincing the build system to work correctly with clang:
  if [ "${CC}" = 'mingw-clang' ]; then

    # Skip 'gltests' build due to errors like this:
    #   ./signal.h:922:3: error: unknown type name 'uid_t'; did you mean 'pid_t'?
    sed -i.bak 's| gltests||g' ./Makefile.am

    export CC='clang'
    if [ "${_OS}" != 'win' ]; then
      export options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
      LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
      [ "${_OS}" = 'linux' ] && ldonly="${ldonly} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
    fi
    export AR=${_CCPREFIX}ar
    export NM=${_CCPREFIX}nm
    export RANLIB=${_CCPREFIX}ranlib
    export RC=${_CCPREFIX}windres
  else
    export CC="${_CCPREFIX}gcc -static-libgcc"
  fi

  export CFLAGS="${LDFLAGS} -fno-ident"
  LDFLAGS="${LDFLAGS}${ldonly}"
  [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"
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
    --prefix=/usr/local \
    --silent
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Build fixups for clang

  # 'configure' misdetects CC=clang as MSVC and then uses '.lib'
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

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
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

  ../_pkg.sh "$(pwd)/${_ref}"
)
