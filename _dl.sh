#!/bin/sh -x

# Copyright 2015-2016 Viktor Szakats (vszakats.net/harbour)

# - Requires Git for Windows or busybox to run on Windows
# - Requires *_VER_ and *_HASH envvars

set | grep '_VER_='

# Quit if any of the lines fail
set -e

   # mingw
#  curl -fsS -o pack.bin 'https://www.mirrorservice.org/sites/dl.sourceforge.net/pub/sourceforge/m/mi/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/5.3.0/threads-posix/sjlj/x86_64-5.3.0-release-posix-sjlj-rt_v4-rev0.7z'
   curl -fsS -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/5.3.0/threads-posix/sjlj/x86_64-5.3.0-release-posix-sjlj-rt_v4-rev0.7z'
   openssl dgst -sha256 pack.bin | grep -q ec28b6640ad4f183be7afcd6e9c5eabb24b89729ca3fec7618755555b5d70c19
   # Will unpack into "./mingw64"
   7z x -y pack.bin > /dev/null
   rm pack.bin

   # zlib
   # Using zlib headers and static libraries bundled with mingw-w64
#  curl -fsS -o pack.bin -L --proto-redir =https "https://github.com/madler/zlib/archive/v${ZLIB_VER_}.tar.gz"
#  openssl dgst -sha256 pack.bin | grep -q "${ZLIB_HASH}"
#  tar -xvf pack.bin > /dev/null 2>&1
#  rm pack.bin
#  mv zlib-* zlib

   # nghttp2
   curl -fsS -o pack.bin -L --proto-redir =https "https://github.com/tatsuhiro-t/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.bz2"
   openssl dgst -sha256 pack.bin | grep -q "${NGHTTP2_HASH}"
   tar -xvf pack.bin > /dev/null 2>&1
   rm pack.bin
   mv nghttp2-* nghttp2

   if [ "${APPVEYOR_REPO_BRANCH#*libressl*}" != "${APPVEYOR_REPO_BRANCH}" ] ; then
      # libressl
      curl -fsS -o pack.bin "http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER_}.tar.gz"
      openssl dgst -sha256 pack.bin | grep -q "${LIBRESSL_HASH}"
      tar -xvf pack.bin > /dev/null 2>&1 || true
      rm pack.bin
      mv libressl-* libressl
   else
      # openssl
      curl -fsS -o pack.bin "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz"
      openssl dgst -sha256 pack.bin | grep -q "${OPENSSL_HASH}"
      tar -xvf pack.bin > /dev/null 2>&1 || true
      rm pack.bin
      mv openssl-* openssl
      dos2unix < openssl.diff | patch -p1 -d openssl
   fi

   # librtmp
#  curl -fsS -o pack.bin "https://rtmpdump.mplayerhq.hu/download/rtmpdump-${LIBRTMP_VER_}.tgz"
#  openssl dgst -sha256 pack.bin | grep -q "${LIBRTMP_HASH}"
#  tar -xvf pack.bin > /dev/null 2>&1
#  rm pack.bin
#  mv rtmpdump-* librtmp

   # libssh2
   curl -fsS -o pack.bin -L --proto-redir =https "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VER_}/libssh2-${LIBSSH2_VER_}.tar.gz"
   openssl dgst -sha256 pack.bin | grep -q "${LIBSSH2_HASH}"
   tar -xvf pack.bin > /dev/null 2>&1
   rm pack.bin
   mv libssh2-* libssh2
   dos2unix < libssh2.diff | patch -p1 -d libssh2

   # curl
   curl -fsS -o pack.bin "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2"
   openssl dgst -sha256 pack.bin | grep -q "${CURL_HASH}"
   tar -xvf pack.bin > /dev/null 2>&1
   rm pack.bin
   mv curl-* curl
