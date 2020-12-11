#!/bin/sh -x

# Copyright 2015-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff
export ZSTD_VER_='1.4.5'
export ZSTD_HASH=2c2366874bc449ff539614266d8c0d6ecdb4baf30bb65609c239ab4ed23c03c7
export BROTLI_VER_='1.0.9'
export BROTLI_HASH=f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46
export LIBIDN2_VER_='2.3.0'
export LIBIDN2_HASH=e1cb1db3d2e249a6a3eb6f0946777c2e892d5c5dc7bd91c74394fc3a01cab8b5
export NGHTTP2_VER_='1.42.0'
export NGHTTP2_HASH=c5a7f09020f31247d0d1609078a75efadeccb7e5b86fc2e4389189b1b431fe63
export NGHTTP3_VER_='0.1.90'
export NGHTTP3_HASH=
export NGTCP2_VER_='0.1.90'
export NGTCP2_HASH=
export CARES_VER_='1.17.1'
export CARES_HASH=d73dd0f6de824afd407ce10750ea081af47eba52b8a6cb307d220131ad93fc40
export OPENSSL_VER_='1.1.1i'
export OPENSSL_HASH=e8be6a35fe41d10603c3cc635e93289ed00bf34b79671a3a4de64fcee00d5242
export LIBSSH2_VER_='1.9.0'
export LIBSSH2_HASH=d5fb8bd563305fd1074dda90bd053fb2d29fc4bce048d182f96eaa466dfadafd
export CURL_VER_='7.74.0'
export CURL_HASH=999d5f2c403cf6e25d58319fdd596611e455dd195208746bc6e6d197a77e878b
export OSSLSIGNCODE_VER_='2.1.0'
export OSSLSIGNCODE_HASH=c512931b6fe151297a1c689f88501e20ffc204c4ffe30e7392eb3decf195065b

# Create revision string
# NOTE: Set _REV to empty after bumping CURL_VER_, and
#       set it to 1 then increment by 1 each time bumping a dependency
#       version or pushing a CI rebuild for the master branch.
export _REV=''

[ -z "${_REV}" ] || _REV="_${_REV}"

echo "Build: REV(${_REV})"

# Quit if any of the lines fail
set -e

# Install required component
# TODO: add `--progress-bar off` when pip 10.0.0 is available
if [ "${_OS}" != 'win' ]; then
  pip3 --version
  pip3 --disable-pip-version-check --no-cache-dir install --user pefile
fi

alias curl='curl --user-agent curl --fail --silent --show-error --connect-timeout 15 --max-time 20 --retry 3'
alias gpg='gpg --batch --keyserver-options timeout=15 --keyid-format long'
[ "${_OS}" = 'mac' ] && alias tar='gtar'

gpg_recv_key() {
  # https://keys.openpgp.org/about/api
  req="pks/lookup?op=get&options=mr&exact=on&search=0x$1"
# curl "https://keys.openpgp.org/${req}"     | gpg --import --status-fd 1 || \
  curl "https://pgpkeys.eu/${req}"           | gpg --import --status-fd 1 || \
  curl "https://keyserver.ubuntu.com/${req}" | gpg --import --status-fd 1
}

gpg --version | grep -a -F gpg

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  _patsuf='.dev'
elif [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
  _patsuf='.test'
else
  _patsuf=''
fi

# zlib
curl --output pkg.bin --location --proto-redir =https "https://github.com/madler/zlib/archive/v${ZLIB_VER_}.tar.gz" || exit 1
openssl dgst -sha256 pkg.bin | grep -q -a -F "${ZLIB_HASH}" || exit 1
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f zlib && mv zlib-* zlib
[ -f "zlib${_patsuf}.patch" ] && dos2unix < "zlib${_patsuf}.patch" | patch --batch -N -p1 -d zlib

# zstd
curl --output pkg.bin --location --proto-redir =https "https://github.com/facebook/zstd/releases/download/v${ZSTD_VER_}/zstd-${ZSTD_VER_}.tar.zst" || exit 1
openssl dgst -sha256 pkg.bin | grep -q -a -F "${ZSTD_HASH}" || exit 1
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f zstd && mv zstd-* zstd
[ -f "zstd${_patsuf}.patch" ] && dos2unix < "zstd${_patsuf}.patch" | patch --batch -N -p1 -d zstd

# Relatively high curl binary size + extra dependency overhead aiming mostly
# to optimize webpage download sizes, so allow to disable it.
if [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
  # brotli
  curl --output pkg.bin --location --proto-redir =https "https://github.com/google/brotli/archive/v${BROTLI_VER_}.tar.gz" || exit 1
  openssl dgst -sha256 pkg.bin | grep -q -a -F "${BROTLI_HASH}" || exit 1
  tar -xf pkg.bin || exit 1
  rm pkg.bin
  rm -r -f brotli && mv brotli-* brotli
  [ -f "brotli${_patsuf}.patch" ] && dos2unix < "brotli${_patsuf}.patch" | patch --batch -N -p1 -d brotli
fi

# nghttp2
curl --output pkg.bin --location --proto-redir =https "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.xz" || exit 1
openssl dgst -sha256 pkg.bin | grep -q -a -F "${NGHTTP2_HASH}" || exit 1
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f nghttp2 && mv nghttp2-* nghttp2
[ -f "nghttp2${_patsuf}.patch" ] && dos2unix < "nghttp2${_patsuf}.patch" | patch --batch -N -p1 -d nghttp2

# This significantly increases curl binary sizes, so leave it optional.
if [ "${_BRANCH#*libidn2*}" != "${_BRANCH}" ]; then
  # libidn2
  curl \
    --output pkg.bin "https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VER_}.tar.gz" \
    --output pkg.sig "https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VER_}.tar.gz.sig" || exit 1
  curl 'https://ftp.gnu.org/gnu/gnu-keyring.gpg' \
  | gpg --quiet --import 2>/dev/null
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  openssl dgst -sha256 pkg.bin | grep -q -a -F "${LIBIDN2_HASH}" || exit 1
  tar -xf pkg.bin || exit 1
  rm pkg.bin
  rm -r -f libidn2 && mv libidn2-* libidn2
fi

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ]; then
  # c-ares
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    CARES_VER_='1.13.1-dev'
    curl \
      --output pkg.bin --location --proto-redir =https 'https://github.com/c-ares/c-ares/archive/611a5ef938c2ca92beb51f455323cda4d40119f7.tar.gz' || exit 1
  else
    curl \
      --output pkg.bin --location --proto-redir =https "https://github.com/c-ares/c-ares/releases/download/cares-$(echo "${CARES_VER_}" | tr '.' '_')/c-ares-${CARES_VER_}.tar.gz" \
      --output pkg.sig --location --proto-redir =https "https://github.com/c-ares/c-ares/releases/download/cares-$(echo "${CARES_VER_}" | tr '.' '_')/c-ares-${CARES_VER_}.tar.gz.asc" || exit 1
    gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
    gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
    openssl dgst -sha256 pkg.bin | grep -q -a -F "${CARES_HASH}" || exit 1
  fi
  tar -xf pkg.bin || exit 1
  rm pkg.bin
  rm -r -f c-ares && mv c-ares-* c-ares
  [ -f "c-ares${_patsuf}.patch" ] && dos2unix < "c-ares${_patsuf}.patch" | patch --batch -N -p1 -d c-ares
fi

# openssl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  OPENSSL_VER_='1.1.1-pre1'
  curl --location --proto-redir =https \
    --output pkg.bin 'https://www.openssl.org/source/openssl-3.0.0-alpha9.tar.gz' || exit 1
else
  curl \
    --output pkg.bin "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz" \
    --output pkg.sig "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz.asc" || exit 1
  # From:
  #   https://www.openssl.org/source/
  #   https://www.openssl.org/community/omc.html
  gpg_recv_key 8657ABB260F056B1E5190839D9C4D26D0E604491
  gpg_recv_key 7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  openssl dgst -sha256 pkg.bin | grep -q -a -F "${OPENSSL_HASH}" || exit 1
fi
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f openssl && mv openssl-* openssl
[ -f "openssl${_patsuf}.patch" ] && dos2unix < "openssl${_patsuf}.patch" | patch --batch -N -p1 -d openssl

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.9.1-dev'
  curl \
    --output pkg.bin --location --proto-redir =https 'https://github.com/libssh2/libssh2/archive/53ff2e6da450ac1801704b35b3360c9488161342.tar.gz' || exit 1
else
  curl \
    --output pkg.bin --location --proto-redir =https "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VER_}/libssh2-${LIBSSH2_VER_}.tar.gz" \
    --output pkg.sig --location --proto-redir =https "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VER_}/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  openssl dgst -sha256 pkg.bin | grep -q -a -F "${LIBSSH2_HASH}" || exit 1
fi
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f libssh2 && mv libssh2-* libssh2
[ -f "libssh2${_patsuf}.patch" ] && dos2unix < "libssh2${_patsuf}.patch" | patch --batch -N -p1 -d libssh2

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.59.0-dev'
  curl \
    --output pkg.bin --location --proto-redir =https 'https://github.com/curl/curl/archive/63f6b3b22077c6fd4a75ce4ceac7258509af412c.tar.gz' || exit 1
else
  curl \
    --output pkg.bin --location --proto-redir =https "https://curl.se/download/curl-${CURL_VER_}.tar.xz" \
    --output pkg.sig --location --proto-redir =https "https://curl.se/download/curl-${CURL_VER_}.tar.xz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  openssl dgst -sha256 pkg.bin | grep -q -a -F "${CURL_HASH}" || exit 1
fi
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f curl && mv curl-7* curl
[ -f "curl${_patsuf}.patch" ] && dos2unix < "curl${_patsuf}.patch" | patch --batch -N -p1 -d curl

# osslsigncode
curl --output pkg.bin --location --proto-redir =https "https://github.com/mtrojnar/osslsigncode/releases/download/2.1/osslsigncode-${OSSLSIGNCODE_VER_}.tar.gz" || exit 1
openssl dgst -sha256 pkg.bin | grep -q -a -F "${OSSLSIGNCODE_HASH}" || exit 1
tar -xf pkg.bin || exit 1
rm pkg.bin
rm -r -f osslsigncode && mv osslsigncode-* osslsigncode
[ -f 'osslsigncode.patch' ] && dos2unix < 'osslsigncode.patch' | patch --batch -N -p1 -d osslsigncode

set +e

rm -f pkg.bin pkg.sig
