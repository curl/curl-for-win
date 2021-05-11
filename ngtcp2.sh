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

  # This is pretty much guesswork and this warning remains:
  #    `configure: WARNING: using cross tools not prefixed with host triplet`
  # Even with `_CCPREFIX` provided.
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

  find . -name '*.o'   -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete
  find . -name '*.dll' -delete
  find . -name '*.exe' -delete

  [ -d ../openssl ]  && export OPENSSL_PATH='../../../openssl'
  if [ -n "${OPENSSL_PATH}" ]; then
    export OPENSSL_CFLAGS="-L${OPENSSL_PATH}/lib -I${OPENSSL_PATH}/include"
    export OPENSSL_LIBS='-lssl -lcrypto'
  fi

  export CC="${_CCPREFIX}gcc -static-libgcc"
  export LDFLAGS="${_OPTM}"
  export CFLAGS="${LDFLAGS} -fno-ident"
  [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --enable-lib-only \
    --disable-shared \
    --enable-static \
    --with-openssl \
    '--prefix=/usr/local' \
    --silent
# make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg"  # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

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

  mkdir -p "${_DST}/include/ngtcp2"
  mkdir -p "${_DST}/lib/pkgconfig"

  cp -f -p ${_pkg}/include/ngtcp2/*.h "${_DST}/include/ngtcp2/"
  cp -f -p ${_pkg}/lib/*.a            "${_DST}/lib/"
  cp -f -p ${_pkg}/lib/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"
  cp -f -p NEWS                       "${_DST}/NEWS.txt"
  cp -f -p AUTHORS                    "${_DST}/AUTHORS.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README.rst                 "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
