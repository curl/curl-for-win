#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  # Cross-tasks

  [ "${_OS}" != 'win' ] && options="--build=${_CROSS_HOST} --host=${_TRIPLET}"

  # Build

  rm -r -f pkg

  # Skip building tests
  sed -i.bak 's| tests||g' ./Makefile.am

  [ -f 'Makefile' ] || autoreconf --force --install

  export LDFLAGS="${_OPTM}"
  export CFLAGS='-fno-ident -O3'
  export CPPFLAGS='-DHAVE_DECL_SECUREZEROMEMORY=1'
  [ "${_CRT}" = 'ucrt' ] && CPPFLAGS="${CPPFLAGS} -D_UCRT"
  ldonly=''

  if [ "${_CC}" = 'clang' ]; then
    export CC='clang'
    if [ "${_OS}" != 'win' ]; then
      options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
      LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
      [ "${_OS}" = 'linux' ] && ldonly="${ldonly} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
    fi
    export AR="${_CCPREFIX}ar"
    export NM="${_CCPREFIX}nm"
    export RANLIB="${_CCPREFIX}ranlib"
  else
    export CC="${_CCPREFIX}gcc -static-libgcc"
  fi

  CFLAGS="${LDFLAGS} ${CFLAGS}"
  LDFLAGS="${LDFLAGS}${ldonly}"
  [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"

  # NOTE: root path with spaces breaks all values with '$(pwd)'. But,
  #       autotools breaks on spaces anyway, so let us leave it like that.

  if [ -d ../zlib ]; then
    options="${options} --with-libz"
    # These seem to work better than --with-libz-prefix=:
    CFLAGS="${CFLAGS} -I$(pwd)/../zlib/pkg/usr/local/include"
    LDFLAGS="${LDFLAGS} -L$(pwd)/../zlib/pkg/usr/local/lib"
  fi

  if [ -d ../libressl ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=$(pwd)/../libressl/pkg/usr/local"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DNOCRYPT"
  elif [ -d ../openssl-quic ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=$(pwd)/../openssl-quic/pkg/usr/local"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DOPENSSL_SUPPRESS_DEPRECATED"
  elif [ -d ../openssl ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=$(pwd)/../openssl/pkg/usr/local"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DOPENSSL_SUPPRESS_DEPRECATED"
  else
    options="${options} --with-crypto=wincng"
  fi

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-rpath \
    --disable-debug \
    --enable-hidden-symbols \
    --enable-static \
    --disable-shared \
    --disable-examples-build \
    --prefix=/usr/local \
    --silent
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Build fixups for clang

  # 'configure' misdetects CC=clang as MSVC and then uses '.lib'
  # extension. Rename these to '.a':
  if [ -f "${_pkg}/lib/libssh2.lib" ]; then
    sed -i.bak "s|\.lib'$|.a'|g" "${_pkg}/lib/libssh2.la"
    mv "${_pkg}/lib/libssh2.lib" "${_pkg}/lib/libssh2.a"
  fi

  # Delete .pc and .la files
  rm -r -f ${_pkg}/lib/pkgconfig
  rm -f    ${_pkg}/lib/*.la

  # Make symlink with .lib extension to make autotools work

  for fn in "${_pkg}"/lib/*.a; do
    ln -s "$(basename "${fn}")" "$(echo "${fn}" | sed 's|\.a$|.lib|')"
  done

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/*.a

  touch -c -r "${_ref}" ${_pkg}/lib/*.a
  touch -c -r "${_ref}" ${_pkg}/include/*.h

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/docs"
  mkdir -p "${_DST}/include"
  mkdir -p "${_DST}/lib"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p ${_pkg}/lib/*.a     "${_DST}/lib/"
  cp -f -p ${_pkg}/include/*.h "${_DST}/include/"
  cp -f -p NEWS                "${_DST}/NEWS.txt"
  cp -f -p COPYING             "${_DST}/COPYING.txt"
  cp -f -p README              "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES       "${_DST}/RELEASE-NOTES.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
