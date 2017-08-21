#!/bin/sh -ex

# Copyright 2014-2017 Viktor Szakats <https://github.com/vszakats>
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

  # This is pretty much guesswork and this warning remains:
  #    `configure: WARNING: using cross tools not prefixed with host triplet`
  # Even with `_CCPREFIX` provided.
  if [ "${os}" != 'win' ]; then

    # https://clang.llvm.org/docs/CrossCompilation.html
    unset _HOST
    case "${os}" in
      win)   _HOST='x86_64-pc-mingw32';;
      linux) _HOST='x86_64-pc-linux';;
      mac)   _HOST='x86_64-apple-darwin';;
      bsd)   _HOST='x86_64-pc-bsd';;
    esac

    [ "${_cpu}" = '32' ] && _TARGET='i686-w64-mingw32'
    [ "${_cpu}" = '64' ] && _TARGET='x86_64-w64-mingw32'

    options="--build=${_HOST} --host=${_TARGET}"
  fi

  # Build

  find . -name '*.o'   -type f -delete
  find . -name '*.a'   -type f -delete
  find . -name '*.lo'  -type f -delete
  find . -name '*.la'  -type f -delete
  find . -name '*.lai' -type f -delete
  find . -name '*.Plo' -type f -delete
  find . -name '*.pc'  -type f -delete

  export CC="${_CCPREFIX}gcc -static-libgcc"
  export LDFLAGS="-m${_cpu}"
  export CFLAGS="${LDFLAGS} -fno-ident -U__STRICT_ANSI__ -DNGHTTP2_STATICLIB"
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"
  export CXXFLAGS="${CFLAGS}"

  export ZLIB_CFLAGS='-I../../zlib'
  export ZLIB_LIBS='-L../../zlib -lz'

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --enable-lib-only \
    --disable-shared \
    '--prefix=/usr/local' \
    --silent
# make clean > /dev/null
  make install "DESTDIR=$(pwd)/pkg" > /dev/null

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Make steps for determinism

  readonly _ref='ChangeLog'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/include/nghttp2/*.h
  touch -c -r "${_ref}" ${_pkg}/lib/pkgconfig/*.pc
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/nghttp2"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/include/nghttp2/*.h "${_DST}/include/nghttp2/"
  cp -f -p ${_pkg}/lib/*.a             "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc  "${_DST}/lib/pkgconfig/"
  cp -f -p ChangeLog                   "${_DST}/ChangeLog.txt"
  cp -f -p AUTHORS                     "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                     "${_DST}/COPYING.txt"
  cp -f -p README.rst                  "${_DST}/"

  unix2dos -k "${_DST}"/*.txt
  unix2dos -k "${_DST}"/*.rst

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
