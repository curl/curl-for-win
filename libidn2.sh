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

  [ "${_OS}" != 'win' ] && options="--build=${_CROSS_HOST} --host=${_TRIPLET}"

  # Build

  rm -r -f pkg

  find . -name '*.o'   -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete
  find . -name '*.dll' -delete
  find . -name '*.exe' -delete

  # May be needed in the future if an "Automake version mismatch" occurs:
# if [ ! -f 'Makefile' ]; then
#   autopoint --force
#   autoreconf -i
# fi

  export LDFLAGS="${_OPTM}"
  unset ldonly

  if [ "${CC}" = 'mingw-clang' ]; then
    export CC='clang'
    if [ "${_OS}" != 'win' ]; then
      export options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
      LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
      [ "${_OS}" = 'linux' ] && ldonly="${ldonly} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
    fi
    export AR=${_CCPREFIX}ar
    export NM=${_CCPREFIX}nm
    export RANLIB=${_CCPREFIX}ranlib
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
    --disable-doc \
    --disable-rpath \
    --enable-static \
    --disable-shared \
    --prefix=/usr/local \
    --silent
# make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Build fixups for clang

  # 'configure' misdetects CC=clang as MSVC and then uses '.lib'
  # extension. So rename these to '.a':
  if [ -f "${_pkg}/lib/libidn2.lib" ]; then
    sed -i.bak -E "s|\.lib'$|.a'|g" "${_pkg}/lib/libidn2.la"
    mv "${_pkg}/lib/libidn2.lib" "${_pkg}/lib/libidn2.a"
  fi

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all ${_pkg}/bin/*.exe

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.exe

  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.exe

  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/include/*.h

  # Tests

  ${_WINE} ${_pkg}/bin/idn2.exe --version

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/bin/*.exe          "${_DST}/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/include/*.h        "${_DST}/include/"
  cp -f -p NEWS                       "${_DST}/NEWS.txt"
  cp -f -p AUTHORS                    "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README                     "${_DST}/README.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
