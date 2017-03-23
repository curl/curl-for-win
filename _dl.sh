#!/bin/sh -x

# Copyright 2015-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff
export LIBIDN_VER_='1.33'
export LIBIDN_HASH=44a7aab635bb721ceef6beecc4d49dfd19478325e1b47f3196f7d2acc4930e19
export NGHTTP2_VER_='1.20.0'
export NGHTTP2_HASH=fb29d0500b194f11680203aed21aafab241063ec1397cc51ab5cc0957341141b
export CARES_VER_='1.12.0'
export CARES_HASH=8692f9403cdcdf936130e045c84021665118ee9bfea905d1a76f04d4e6f365fb
export LIBRESSL_VER_='2.4.3'
export LIBRESSL_HASH=bd5726f3e247e7a7d30ce69946d174b8fb92d999d22710c65f176c969812960e
export OPENSSL_VER_='1.1.0e'
export OPENSSL_HASH=57be8618979d80c910728cfc99369bf97b2a1abd8f366ab6ebdee8975ad3874c
export LIBRTMP_VER_='2.4+20151223'
export LIBRTMP_HASH=5c032f5c8cc2937eb55a81a94effdfed3b0a0304b6376147b86f951e225e3ab5
export LIBSSH2_VER_='1.8.0'
export LIBSSH2_HASH=39f34e2f6835f4b992cafe8625073a88e5a28ba78f83e8099610a7b3af4676d4
export CURL_VER_='7.53.1'
export CURL_HASH=1c7207c06d75e9136a944a2e0528337ce76f15b9ec9ae4bb30d703b59bf530e8

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
else
   _patsuf=''
fi

if [ "${os}" = 'win' ]; then
  if [ "${_BRANCH#*extmingw*}" != "${_BRANCH}" ]; then
    # mingw
    curl -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/6.3.0/threads-posix/sjlj/x86_64-6.3.0-release-posix-sjlj-rt_v5-rev1.7z' || exit 1
    openssl dgst -sha256 pack.bin | grep -q 10c40147b1781d0b915e96967becca99c6ffe2d56695a6830721051fe1b62b1f || exit 1
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
curl -o pack.bin -L --proto-redir =https "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.bz2" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${NGHTTP2_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r nghttp2 && mv nghttp2-* nghttp2

# Will increase curl binary sizes by 1MB, so leave this optional.
if [ "${_BRANCH#*libidn*}" != "${_BRANCH}" ]; then
  # libidn
  curl \
    -o pack.bin "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VER_}.tar.gz" \
    -o pack.sig "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VER_}.tar.gz.sig" || exit 1
  curl 'https://ftp.gnu.org/gnu/gnu-keyring.gpg' \
  | gpg -q --import 2> /dev/null
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${LIBIDN_HASH}" || exit 1
  tar -xvf pack.bin > /dev/null 2>&1 || exit 1
  rm pack.bin
  rm -f -r libidn && mv libidn-* libidn
fi

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ]; then
  # c-ares
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    CARES_VER_='1.11.1-dev'
    curl -o pack.bin -L --proto-redir =https https://github.com/c-ares/c-ares/archive/9642b578a2414406ed01ca5db5057adcb47cb633.tar.gz || exit 1
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
    OPENSSL_VER_='1.1.0-dev'
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
  curl -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/7934c9ce2a029c43e3642a492d3b9e494d1542be.tar.gz || exit 1
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
  CURL_VER_='7.51.1-dev'
  curl -o pack.bin -L --proto-redir =https https://github.com/curl/curl/archive/73878278d86f22285681db2e75eb1c711bfab41b.tar.gz || exit 1
else
  curl \
    -o pack.bin "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2" \
    -o pack.sig "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2.asc" || exit 1
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
