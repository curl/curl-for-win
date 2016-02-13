#!/bin/sh -x

# Copyright 2015-2016 Viktor Szakats (vszakats.net/harbour)
# See LICENSE.md

export ZLIB_VER_='1.2.8'
export ZLIB_HASH=e380bd1bdb6447508beaa50efc653fe45f4edc1dafe11a251ae093e0ee97db9a
export NGHTTP2_VER_='1.7.0'
export NGHTTP2_HASH=9447ddfc2888c5d2d7ef27370b9f911c0263430666682105ca4066dcd88708f0
export LIBRESSL_VER_='2.3.2'
export LIBRESSL_HASH=80f45fae4859f161b1980cad846d4217417d0c89006ad29c0ea8c88da564a96a
export OPENSSL_VER_='1.0.2f'
export OPENSSL_HASH=932b4ee4def2b434f85435d9e3e19ca8ba99ce9a065a61524b429a9d5e9b2e9c
export LIBRTMP_VER_='2.4+20151223'
export LIBRTMP_HASH=f8eb8d0c8ed085c90666ba0e8fbe0e960e0cf0c2a58604fda3ed85a28f2ef5f6
export LIBSSH2_VER_='1.6.0'
export LIBSSH2_HASH=5a202943a34a1d82a1c31f74094f2453c207bf9936093867f41414968c8e8215
export CURL_VER_='7.47.1'
export CURL_HASH=ddc643ab9382e24bbe4747d43df189a0a6ce38fcb33df041b9cb0b3cd47ae98f

# Quit if any of the lines fail
set -e

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   PATSUF='.dev'
else
   PATSUF=''
fi

if [ "${_BRANCH#*msysmingw*}" = "${_BRANCH}" ] ; then
   # mingw
   curl -fsS -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/5.3.0/threads-posix/sjlj/x86_64-5.3.0-release-posix-sjlj-rt_v4-rev0.7z'
   openssl dgst -sha256 pack.bin | grep -q ec28b6640ad4f183be7afcd6e9c5eabb24b89729ca3fec7618755555b5d70c19
   # Will unpack into "./mingw64"
   7z x -y pack.bin > /dev/null
   rm pack.bin
fi

# nghttp2
curl -fsS -o pack.bin -L --proto-redir =https "https://github.com/tatsuhiro-t/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.bz2"
openssl dgst -sha256 pack.bin | grep -q "${NGHTTP2_HASH}"
tar -xvf pack.bin > /dev/null 2>&1
rm pack.bin
rm -f -r nghttp2 && mv nghttp2-* nghttp2

if [ "${_BRANCH#*libressl*}" != "${_BRANCH}" ] ; then
   # libressl
   curl -fsS -o pack.bin "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER_}.tar.gz"
   openssl dgst -sha256 pack.bin | grep -q "${LIBRESSL_HASH}"
   tar -xvf pack.bin > /dev/null 2>&1 || true
   rm pack.bin
   rm -f -r libressl && mv libressl-* libressl
else
   # openssl
   if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
      OPENSSL_VER_='1.1.0-dev'
      curl -fsS -o pack.bin -L --proto-redir =https https://github.com/openssl/openssl/archive/master.tar.gz
   else
      curl -fsS -o pack.bin "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz"
      openssl dgst -sha256 pack.bin | grep -q "${OPENSSL_HASH}"
   fi
   tar -xvf pack.bin > /dev/null 2>&1 || true
   rm pack.bin
   rm -f -r openssl && mv openssl-* openssl
   [ -f "openssl${PATSUF}.diff" ] && dos2unix < "openssl${PATSUF}.diff" | patch -N -p1 -d openssl
fi

# Do not include this by default to avoid an unnecessary libcurl dependency
# and potential licensing issues.
if [ "${_BRANCH#*librtmp*}" != "${_BRANCH}" ] ; then
   # librtmp
   curl -fsS -o pack.bin 'https://mirrorservice.org/sites/ftp.debian.org/debian/pool/main/r/rtmpdump/rtmpdump_2.4+20151223.gitfa8646d.orig.tar.gz'
   openssl dgst -sha256 pack.bin | grep -q "${LIBRTMP_HASH}"
   tar -xvf pack.bin > /dev/null 2>&1
   rm pack.bin
   rm -f -r librtmp && mv rtmpdump-* librtmp
fi

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   LIBSSH2_VER_='1.6.1-dev'
   curl -fsS -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/e64260a11792fb3242441c3f190ac0a6bf7591eb.tar.gz
else
   curl -fsS -o pack.bin -L --proto-redir =https "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VER_}/libssh2-${LIBSSH2_VER_}.tar.gz"
   openssl dgst -sha256 pack.bin | grep -q "${LIBSSH2_HASH}"
fi
tar -xvf pack.bin > /dev/null 2>&1
rm pack.bin
rm -f -r libssh2 && mv libssh2-* libssh2
[ -f "libssh2${PATSUF}.diff" ] && dos2unix < "libssh2${PATSUF}.diff" | patch -N -p1 -d libssh2

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   CURL_VER_='7.47.2-dev'
   curl -fsS -o pack.bin -L --proto-redir =https https://github.com/curl/curl/archive/c3aac489195526c23190fcfe4ce63cbe49ea00e6.tar.gz
else
   curl -fsS -o pack.bin "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2"
   openssl dgst -sha256 pack.bin | grep -q "${CURL_HASH}"
fi
tar -xvf pack.bin > /dev/null 2>&1
rm pack.bin
rm -f -r curl && mv curl-* curl

set +e
