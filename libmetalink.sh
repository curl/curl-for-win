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
    export RC=${_CCPREFIX}windres
  else
    export CC="${_CCPREFIX}gcc -static-libgcc"
  fi
  export AUTOMAKE=automake
  export ACLOCAL=aclocal
  export EXPAT_CFLAGS='-I../../expat/pkg/usr/local/include'
  export EXPAT_LIBS='-lexpat'

  # Terrible patch to get around autotool complaining about a version mismatch.
  # There must be a better solution to this.
  sed -i.bak "s|1.14.1|$("${ACLOCAL}" --version | head -1 | grep -a -o -E '[0-9.]+')|g" ./aclocal.m4

  # Skip building example tool. There is no 'configure' option for this.
  sed -i.bak 's| examples||g' doc/Makefile.am

  export CFLAGS="${LDFLAGS} -fno-ident -DXML_STATIC"
  LDFLAGS="${LDFLAGS}${ldonly}"
  [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"

  # Disable _mkgmtime() in 32-bit build for compatibility with old Windows
  # versions where msvcrt.dll does not export function _mkgmtime32(), that
  # this function is being mapped to.
  [ "${_CPU}" = 'x86' ] && sed -i.bak 's|_mkgmtime|_mkgmtime_do_not_detect|g' ./configure

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --enable-static \
    --disable-shared \
    --disable-xmltest \
    --with-libexpat=yes \
    --with-libxml2=no \
    --prefix=/usr/local
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  [ "${_CPU}" = 'x86' ] && mv ./configure.bak ./configure

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Build fixups for clang

  # 'configure' misdetects CC=clang as MSVC and then uses '.lib'
  # extension. So rename these to '.a':
  if [ -f "${_pkg}/lib/libmetalink.lib" ]; then
    sed -i.bak -E "s|\.lib'$|.a'|g" "${_pkg}/lib/libmetalink.la"
    mv "${_pkg}/lib/libmetalink.lib" "${_pkg}/lib/libmetalink.a"
  fi

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/include/metalink/*.h

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/metalink"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/lib/*.a              "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc   "${_DST}/lib/pkgconfig/"
  cp -f -p ${_pkg}/include/metalink/*.h "${_DST}/include/metalink/"
  cp -f -p NEWS                         "${_DST}/NEWS.txt"
  cp -f -p AUTHORS                      "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                      "${_DST}/COPYING.txt"
  cp -f -p README                       "${_DST}/README.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
