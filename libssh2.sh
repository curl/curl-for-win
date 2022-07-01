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

  rm -r -f "${_PKGDIR}"

  [ -f 'Makefile' ] || autoreconf --force --install

  options="${_CONFIGURE_GLOBAL}"
  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  CPPFLAGS="${CPPFLAGS} -DHAVE_DECL_SECUREZEROMEMORY=1 -DLIBSSH2_CLEAR_MEMORY"

  # NOTE: root path with spaces breaks all values with '${_TOP}'. But,
  #       autotools breaks on spaces anyway, so let us leave it like that.

  if [ -d ../zlib ]; then
    options="${options} --with-libz"
    # These seem to work better than --with-libz-prefix=:
    CFLAGS="${CFLAGS} -I${_TOP}/zlib/${_PKGDIR}${_PREFIX}/include"
    LDFLAGS="${LDFLAGS} -L${_TOP}/zlib/${_PKGDIR}${_PREFIX}/lib"
  fi

  if [ -d ../libressl ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOP}/libressl/${_PKGDIR}${_PREFIX}"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DNOCRYPT"
    LDFLAGS="${LDFLAGS} -lbcrypt"
  elif [ -d ../openssl-quic ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOP}/openssl-quic/${_PKGDIR}${_PREFIX}"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DOPENSSL_SUPPRESS_DEPRECATED"
    LDFLAGS="${LDFLAGS} -lbcrypt"
  elif [ -d ../openssl ]; then
    options="${options} --with-crypto=openssl --with-libssl-prefix=${_TOP}/openssl/${_PKGDIR}${_PREFIX}"
    CPPFLAGS="${CPPFLAGS} -DHAVE_EVP_AES_128_CTR=1 -DOPENSSL_SUPPRESS_DEPRECATED"
    LDFLAGS="${LDFLAGS} -lbcrypt"
  else
    options="${options} --with-crypto=wincng"
  fi

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-rpath \
    --disable-debug \
    --enable-hidden-symbols \
    --enable-static \
    --disable-shared \
    --disable-examples-build \
    "--prefix=${_PREFIX}" --silent
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg="${_PKGDIR}${_PREFIX}"

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
