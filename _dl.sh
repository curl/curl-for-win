#!/bin/sh -x

# Copyright 2015-2018 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff
export BROTLI_VER_='1.0.4'
export BROTLI_HASH=2268a3dff1cc36e18549e89a51ee0cd9513908a977d56d6a1f9d4c61c2af37c3
export LIBIDN2_VER_='2.0.4'
export LIBIDN2_HASH=644b6b03b285fb0ace02d241d59483d98bc462729d8bb3608d5cad5532f3d2f0
export NGHTTP2_VER_='1.32.0'
export NGHTTP2_HASH=700a89d59fcc55acc2b18184001bfb3220fa6a6e543486aca35f40801cba6f7d
export CARES_VER_='1.14.0'
export CARES_HASH=45d3c1fd29263ceec2afc8ff9cd06d5f8f889636eb4e80ce3cc7f0eaf7aadc6e
export OPENSSL_VER_='1.1.0h'
export OPENSSL_HASH=5835626cde9e99656585fc7aaa2302a73a7e1340bf8c14fd635a62c66802a517
export LIBSSH2_VER_='1.8.0'
export LIBSSH2_HASH=39f34e2f6835f4b992cafe8625073a88e5a28ba78f83e8099610a7b3af4676d4
export CURL_VER_='7.60.0'
export CURL_HASH=8736ff8ded89ddf7e926eec7b16f82597d029fc1469f3a551f1fafaac164e6a0

# Quit if any of the lines fail
set -e

# Detect host OS
case "$(uname)" in
  *_NT*)   os='win';;
  Linux*)  os='linux';;
  Darwin*) os='mac';;
  *BSD)    os='bsd';;
esac

if [ "${os}" != 'win' ]; then
  # Install required component
  # TODO: add `--progress-bar off` when pip 10.0.0 is available
  pip3 --version
  pip3 --disable-pip-version-check install --user pefile
fi

alias curl='curl -fsS --connect-timeout 15 --retry 3'
alias gpg='gpg --batch --keyserver-options timeout=15 --keyid-format LONG'

gpg_recv_keys() {
  req="pks/lookup?search=0x$1&op=get"
  if ! curl "https://pgp.mit.edu/${req}" | gpg --import --status-fd 1; then
    curl "https://sks-keyservers.net/${req}" | gpg --import --status-fd 1
  fi
}

gpg --version | grep gpg

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  _patsuf='.dev'
elif [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
  _patsuf='.test'
else
  _patsuf=''
fi

# zlib
curl -o pack.bin -L --proto-redir =https "https://github.com/madler/zlib/archive/v${ZLIB_VER_}.tar.gz" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${ZLIB_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r zlib && mv zlib-* zlib
[ -f "zlib${_patsuf}.patch" ] && dos2unix < "zlib${_patsuf}.patch" | patch --batch -N -p1 -d zlib

# Relatively high curl binary size + extra dependency overhead aiming mostly
# to optimize webpage download sizes, so allow to disable it.
if [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
  # brotli
  curl -o pack.bin -L --proto-redir =https "https://github.com/google/brotli/archive/v${BROTLI_VER_}.tar.gz" || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${BROTLI_HASH}" || exit 1
  tar -xvf pack.bin > /dev/null 2>&1 || exit 1
  rm pack.bin
  rm -f -r brotli && mv brotli-* brotli
  [ -f "brotli${_patsuf}.patch" ] && dos2unix < "brotli${_patsuf}.patch" | patch --batch -N -p1 -d brotli
fi

# nghttp2
curl -o pack.bin -L --proto-redir =https "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.xz" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${NGHTTP2_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r nghttp2 && mv nghttp2-* nghttp2
[ -f "nghttp2${_patsuf}.patch" ] && dos2unix < "nghttp2${_patsuf}.patch" | patch --batch -N -p1 -d nghttp2

# This significantly increases curl binary sizes, so leave it optional.
if [ "${_BRANCH#*libidn2*}" != "${_BRANCH}" ]; then
  # libidn2
  curl \
    -o pack.bin "https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VER_}.tar.gz" \
    -o pack.sig "https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VER_}.tar.gz.sig" || exit 1
  curl 'https://ftp.gnu.org/gnu/gnu-keyring.gpg' \
  | gpg -q --import 2> /dev/null
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${LIBIDN2_HASH}" || exit 1
  tar -xvf pack.bin > /dev/null 2>&1 || exit 1
  rm pack.bin
  rm -f -r libidn2 && mv libidn2-* libidn2
fi

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ]; then
  # c-ares
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    CARES_VER_='1.13.1-dev'
    curl -o pack.bin -L --proto-redir =https https://github.com/c-ares/c-ares/archive/611a5ef938c2ca92beb51f455323cda4d40119f7.tar.gz || exit 1
  else
    curl \
      -o pack.bin "https://c-ares.haxx.se/download/c-ares-${CARES_VER_}.tar.gz" \
      -o pack.sig "https://c-ares.haxx.se/download/c-ares-${CARES_VER_}.tar.gz.asc" || exit 1
    gpg_recv_keys 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
    gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
    openssl dgst -sha256 pack.bin | grep -q "${CARES_HASH}" || exit 1
  fi
  tar -xvf pack.bin > /dev/null 2>&1 || exit 1
  rm pack.bin
  rm -f -r c-ares && mv c-ares-* c-ares
  [ -f "c-ares${_patsuf}.patch" ] && dos2unix < "c-ares${_patsuf}.patch" | patch --batch -N -p1 -d c-ares
fi

# openssl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  OPENSSL_VER_='1.1.1-pre1'
  curl -o pack.bin -L --proto-redir =https https://www.openssl.org/source/openssl-1.1.1-pre1.tar.gz || exit 1
else
  curl \
    -o pack.bin "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz" \
    -o pack.sig "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz.asc" || exit 1
  # From https://www.openssl.org/community/team.html
  gpg_recv_keys 8657ABB260F056B1E5190839D9C4D26D0E604491
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${OPENSSL_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r openssl && mv openssl-* openssl
[ -f "openssl${_patsuf}.patch" ] && dos2unix < "openssl${_patsuf}.patch" | patch --batch -N -p1 -d openssl

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.8.1-dev'
  curl -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/bcd492163b71608f8e46cdc864741d6c566ce9bc.tar.gz || exit 1
else
  curl \
    -o pack.bin -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz" \
    -o pack.sig -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
  gpg_recv_keys 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${LIBSSH2_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r libssh2 && mv libssh2-* libssh2
[ -f "libssh2${_patsuf}.patch" ] && dos2unix < "libssh2${_patsuf}.patch" | patch --batch -N -p1 -d libssh2

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.59.0-dev'
  curl -o pack.bin -L --proto-redir =https https://github.com/curl/curl/archive/63f6b3b22077c6fd4a75ce4ceac7258509af412c.tar.gz || exit 1
else
  curl \
    -o pack.bin "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.xz" \
    -o pack.sig "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.xz.asc" || exit 1
  gpg_recv_keys 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${CURL_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r curl && mv curl-* curl
[ -f "curl${_patsuf}.patch" ] && dos2unix < "curl${_patsuf}.patch" | patch --batch -N -p1 -d curl

set +e

rm -f pack.bin pack.sig
