#!/bin/sh -x

# Copyright 2015-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export ZLIB_VER_='1.2.8'
export ZLIB_HASH=e380bd1bdb6447508beaa50efc653fe45f4edc1dafe11a251ae093e0ee97db9a
export LIBIDN_VER_='1.33'
export LIBIDN_HASH=44a7aab635bb721ceef6beecc4d49dfd19478325e1b47f3196f7d2acc4930e19
export NGHTTP2_VER_='1.14.0'
export NGHTTP2_HASH=9516918c1bda50b7d09c308926448ca756b887ee051c94fe6835749ca41eaba2
export CARES_VER_='1.11.0'
export CARES_HASH=b3612e6617d9682928a1d50c1040de4db6519f977f0b25d40cf1b632900b3efd
export LIBRESSL_VER_='2.4.2'
export LIBRESSL_HASH=5f87d778e5d62822d60e38fa9621c1c5648fc559d198ba314bd9d89cbf67d9e3
export OPENSSL_VER_='1.0.2h'
export OPENSSL_HASH=1d4007e53aad94a5b2002fe045ee7bb0b3d98f1a47f8b2bc851dcd1c74332919
export LIBRTMP_VER_='2.4+20151223'
export LIBRTMP_HASH=5c032f5c8cc2937eb55a81a94effdfed3b0a0304b6376147b86f951e225e3ab5
export LIBSSH2_VER_='1.7.0'
export LIBSSH2_HASH=e4561fd43a50539a8c2ceb37841691baf03ecb7daf043766da1b112e4280d584
export CURL_VER_='7.50.1'
export CURL_HASH=3c12c5f54ccaa1d40abc65d672107dcc75d3e1fcb38c267484334280096e5156

# Quit if any of the lines fail
set -e

# Install required component
python -m pip --disable-pip-version-check install --upgrade pip
python -m pip install pefile

alias curl='curl -fsS --connect-timeout 15 --retry 3'
alias gpg='gpg --batch --keyid-format LONG'

gpg_recv_keys() {
   if ! gpg -q --keyserver hkps://pgp.mit.edu --recv-keys "$@" ; then
      gpg -q --keyserver hkps://sks-keyservers.net --recv-keys "$@"
   fi
}

gpg --version | grep gpg

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   _patsuf='.dev'
else
   _patsuf=''
fi

if [ "${_BRANCH#*msysmingw*}" = "${_BRANCH}" ] ; then
   # mingw
   curl -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/6.1.0/threads-posix/sjlj/x86_64-6.1.0-release-posix-sjlj-rt_v5-rev0.7z' || exit 1
   openssl dgst -sha256 pack.bin | grep -q 39edf7d7938c891b45b06e8f0879aef0b366a63f519725a8af3f5b6a651c2849 || exit 1
   # Will unpack into './mingw64'
   7z x -y pack.bin > /dev/null || exit 1
   rm pack.bin
fi

# nghttp2
curl -o pack.bin -L --proto-redir =https "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.bz2" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${NGHTTP2_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r nghttp2 && mv nghttp2-* nghttp2

# Will increase curl binary sizes by 1MB, so leave this optional.
if [ "${_BRANCH#*libidn*}" != "${_BRANCH}" ] ; then
   # libidn
   curl -o pack.bin "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VER_}.tar.gz" || exit 1
   curl -o pack.sig "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VER_}.tar.gz.sig" || exit 1
   curl 'https://ftp.gnu.org/gnu/gnu-keyring.gpg' | \
      gpg -q --import 2> /dev/null
   gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBIDN_HASH}" || exit 1
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r libidn && mv libidn-* libidn
fi

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ] ; then
   # c-ares
   if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
      CARES_VER_='1.11.1-dev'
      curl -o pack.bin -L --proto-redir =https https://github.com/c-ares/c-ares/archive/9642b578a2414406ed01ca5db5057adcb47cb633.tar.gz || exit 1
   else
      curl -o pack.bin "http://c-ares.haxx.se/download/c-ares-${CARES_VER_}.tar.gz" || exit 1
      curl -o pack.sig "http://c-ares.haxx.se/download/c-ares-${CARES_VER_}.tar.gz.asc" || exit 1
      gpg_recv_keys 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2 914C533DF9B2ADA2204F586D78E11C6B279D5C91
      gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
      openssl dgst -sha256 pack.bin | grep -q "${CARES_HASH}" || exit 1
   fi
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r c-ares && mv c-ares-* c-ares
   [ -f "c-ares${_patsuf}.diff" ] && dos2unix < "c-ares${_patsuf}.diff" | patch -N -p1 -d c-ares
fi

if [ "${_BRANCH#*libressl*}" != "${_BRANCH}" ] ; then
   # libressl
   curl -o pack.bin "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER_}.tar.gz" || exit 1
   curl -o pack.sig "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER_}.tar.gz.asc" || exit 1
   gpg_recv_keys A1EB079B8D3EB92B4EBD3139663AF51BD5E4D8D5
   gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBRESSL_HASH}" || exit 1
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r libressl && mv libressl-* libressl
else
   # openssl
   if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
      OPENSSL_VER_='1.1.0-dev'
      curl -o pack.bin -L --proto-redir =https https://github.com/openssl/openssl/archive/master.tar.gz || exit 1
   else
      curl -o pack.bin "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz" || exit 1
      curl -o pack.sig "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz.asc" || exit 1
      # From https://www.openssl.org/community/team.html
      gpg_recv_keys 8657ABB260F056B1E5190839D9C4D26D0E604491
      gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
      openssl dgst -sha256 pack.bin | grep -q "${OPENSSL_HASH}" || exit 1
   fi
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r openssl && mv openssl-* openssl
   [ -f "openssl${_patsuf}.diff" ] && dos2unix < "openssl${_patsuf}.diff" | patch -N -p1 -d openssl
fi

# Do not include this by default to avoid an unnecessary libcurl dependency
# and potential licensing issues.
if [ "${_BRANCH#*librtmp*}" != "${_BRANCH}" ] ; then
   # librtmp
   curl -o pack.bin 'https://mirrorservice.org/sites/ftp.debian.org/debian/pool/main/r/rtmpdump/rtmpdump_2.4+20151223.gitfa8646d.1.orig.tar.gz' || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBRTMP_HASH}" || exit 1
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r librtmp && mv rtmpdump-* librtmp
fi

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   LIBSSH2_VER_='1.7.1-dev'
   curl -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/7934c9ce2a029c43e3642a492d3b9e494d1542be.tar.gz || exit 1
else
   curl -o pack.bin -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz" || exit 1
   curl -o pack.sig -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
   gpg_recv_keys 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2 914C533DF9B2ADA2204F586D78E11C6B279D5C91
   gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBSSH2_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r libssh2 && mv libssh2-* libssh2
[ -f "libssh2${_patsuf}.diff" ] && dos2unix < "libssh2${_patsuf}.diff" | patch -N -p1 -d libssh2

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   CURL_VER_='7.50.2-dev'
   curl -o pack.bin -L --proto-redir =https https://github.com/curl/curl/archive/73878278d86f22285681db2e75eb1c711bfab41b.tar.gz || exit 1
else
   curl -o pack.bin "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2" || exit 1
   curl -o pack.sig "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2.asc" || exit 1
   gpg_recv_keys 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
   gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${CURL_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r curl && mv curl-* curl
[ -f "curl${_patsuf}.diff" ] && dos2unix < "curl${_patsuf}.diff" | patch -N -p1 -d curl

set +e
