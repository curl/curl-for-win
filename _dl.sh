#!/bin/sh -x

# Copyright 2015-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff
export LIBIDN2_VER_='2.0.3'
export LIBIDN2_HASH=4335149ce7a5c615edb781574d38f658672780331064fb17354a10e11a5308cd
export NGHTTP2_VER_='1.25.0'
export NGHTTP2_HASH=9553f144e60aa0d7bc5245df1c0f6a867a9fd9dc35ed6f358c6122a844d52f62
export CARES_VER_='1.13.0'
export CARES_HASH=03f708f1b14a26ab26c38abd51137640cb444d3ec72380b21b20f1a8d2861da7
export LIBRESSL_VER_='2.5.5'
export LIBRESSL_HASH=e57f5e3d5842a81fe9351b6e817fcaf0a749ca4ef35a91465edba9e071dce7c4
export OPENSSL_VER_='1.1.0f'
export OPENSSL_HASH=12f746f3f2493b2f39da7ecf63d7ee19c6ac9ec6a4fcd8c229da8a522cb12765
export LIBRTMP_VER_='2.4+20151223'
export LIBRTMP_HASH=5c032f5c8cc2937eb55a81a94effdfed3b0a0304b6376147b86f951e225e3ab5
export LIBSSH2_VER_='1.8.0'
export LIBSSH2_HASH=39f34e2f6835f4b992cafe8625073a88e5a28ba78f83e8099610a7b3af4676d4
export CURL_VER_='7.55.1'
export CURL_HASH=3eafca6e84ecb4af5f35795dee84e643d5428287e88c041122bb8dac18676bb7

# Quit if any of the lines fail
set -e

# Detect host OS
case "$(uname)" in
  *_NT*)   os='win';;
  Linux*)  os='linux';;
  Darwin*) os='mac';;
  *BSD)    os='bsd';;
esac

# Install required component
# TODO: add `--progress-bar off` when pip 9.1.0 hits the drives
python -m pip --disable-pip-version-check install --upgrade pip
python -m pip install pefile

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

if [ "${os}" = 'win' ]; then
  if [ "${_BRANCH#*mingwext*}" != "${_BRANCH}" ]; then
    # mingw
    curl -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/7.1.0/threads-posix/sjlj/x86_64-7.1.0-release-posix-sjlj-rt_v5-rev0.7z' || exit 1
    openssl dgst -sha256 pack.bin | grep -q a117ec6126c9cc31e89498441d66af3daef59439c36686e80cebf29786e17c13 || exit 1
    # Will unpack into './mingw64'
    7z x -y pack.bin > /dev/null || exit 1
    rm pack.bin
  fi
fi

# zlib
curl -o pack.bin -L --proto-redir =https "https://github.com/madler/zlib/archive/v${ZLIB_VER_}.tar.gz" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${ZLIB_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r zlib && mv zlib-* zlib
[ -f "zlib${_patsuf}.patch" ] && dos2unix < "zlib${_patsuf}.patch" | patch -N -p1 -d zlib

# nghttp2
curl -o pack.bin -L --proto-redir =https "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.xz" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${NGHTTP2_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r nghttp2 && mv nghttp2-* nghttp2

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
  [ -f "c-ares${_patsuf}.patch" ] && dos2unix < "c-ares${_patsuf}.patch" | patch -N -p1 -d c-ares
fi

if [ "${_BRANCH#*libressl*}" != "${_BRANCH}" ]; then
  # libressl
  curl \
    -o pack.bin "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER_}.tar.gz" \
    -o pack.sig "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER_}.tar.gz.asc" || exit 1
  gpg_recv_keys A1EB079B8D3EB92B4EBD3139663AF51BD5E4D8D5
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${LIBRESSL_HASH}" || exit 1
  tar -xvf pack.bin > /dev/null 2>&1 || exit 1
  rm pack.bin
  rm -f -r libressl && mv libressl-* libressl
else
  # openssl
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    OPENSSL_VER_='1.1.1-dev'
    curl -o pack.bin -L --proto-redir =https https://github.com/openssl/openssl/archive/master.tar.gz || exit 1
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
  [ -f "openssl${_patsuf}.patch" ] && dos2unix < "openssl${_patsuf}.patch" | patch -N -p1 -d openssl
fi

# Do not include this by default to avoid an unnecessary libcurl dependency
# and potential licensing issues.
if [ "${_BRANCH#*librtmp*}" != "${_BRANCH}" ]; then
  # librtmp
  curl -o pack.bin 'https://mirrorservice.org/sites/ftp.debian.org/debian/pool/main/r/rtmpdump/rtmpdump_2.4+20151223.gitfa8646d.1.orig.tar.gz' || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${LIBRTMP_HASH}" || exit 1
  tar -xvf pack.bin > /dev/null 2>&1 || exit 1
  rm pack.bin
  rm -f -r librtmp && mv rtmpdump-* librtmp
fi

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.8.1-dev'
  curl -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/fe186fef3a66f68fac1de8003efd36193a3ead47.tar.gz || exit 1
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
[ -f "libssh2${_patsuf}.patch" ] && dos2unix < "libssh2${_patsuf}.patch" | patch -N -p1 -d libssh2

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.56.0-dev'
  curl -o pack.bin -L --proto-redir =https https://github.com/curl/curl/archive/c86e21b624570e498e71d7d35c82b7ff193104c7.tar.gz || exit 1
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
[ -f "curl${_patsuf}.patch" ] && dos2unix < "curl${_patsuf}.patch" | patch -N -p1 -d curl

set +e

rm -f pack.bin pack.sig
