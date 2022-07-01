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

  # Build

  rm -r -f pkg

  [ -f 'Makefile' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -fno-ident -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  if [ "${_CC}" = 'clang' ]; then
    export RC="${_CCPREFIX}windres"
    export AR="${_CCPREFIX}ar"
    export NM="${_CCPREFIX}nm"
    export RANLIB="${_CCPREFIX}ranlib"
  fi

  CPPFLAGS="${CPPFLAGS} -DHAVE_DECL_SECUREZEROMEMORY=1 -DLIBSSH2_CLEAR_MEMORY"

  # NOTE: root path with spaces breaks all values with '$(pwd)'. But,
  #       autotools breaks on spaces anyway, so let us leave it like that.

  if [ -d ../zlib ]; then
    options="${options} --with-libz"
    # These seem to work better than --with-libz-prefix=:
    CFLAGS="${CFLAGS} -I${_TOPDIR}/zlib/pkg/usr/local/include"
    LDFLAGS="${LDFLAGS} -L${_TOPDIR}/zlib/pkg/usr/local/lib"
  fi

  if [ -d ../libressl ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOPDIR}/libressl/pkg/usr/local"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DNOCRYPT"
    LDFLAGS="${LDFLAGS} -lbcrypt"
  elif [ -d ../openssl-quic ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOPDIR}/openssl-quic/pkg/usr/local"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DOPENSSL_SUPPRESS_DEPRECATED"
    LDFLAGS="${LDFLAGS} -lbcrypt"
  elif [ -d ../openssl ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOPDIR}/openssl/pkg/usr/local"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DOPENSSL_SUPPRESS_DEPRECATED"
    LDFLAGS="${LDFLAGS} -lbcrypt"
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
    "--prefix=${_PREFIX}" \
    --silent
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg="pkg${_PREFIX}"

  # Delete .pc and .la files
  rm -r -f "${_pkg}"/lib/pkgconfig
  rm -f    "${_pkg}"/lib/*.la

  # Make steps for determinism

  readonly _ref='NEWS'

  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/lib/*.a
  touch -c -r "${_ref}" "${_pkg}"/include/*.h

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
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p "${_pkg}"/lib/*.a     "${_DST}/lib/"
  cp -f -p "${_pkg}"/include/*.h "${_DST}/include/"
  cp -f -p NEWS                  "${_DST}/NEWS.txt"
  cp -f -p COPYING               "${_DST}/COPYING.txt"
  cp -f -p README                "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES         "${_DST}/RELEASE-NOTES.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
