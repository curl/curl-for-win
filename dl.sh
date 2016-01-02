#!/bin/sh -x

# Copyright 2015-2016 Viktor Szakats (vszakats.net/harbour)

# - Requires Git for Windows or busybox to run on Windows
# - Requires VER_* envvars

# Quit if any of the lines fail
set -e

  # mingw
# curl -fsS -o pack.bin 'https://www.mirrorservice.org/sites/dl.sourceforge.net/pub/sourceforge/m/mi/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/5.3.0/threads-posix/sjlj/x86_64-5.3.0-release-posix-sjlj-rt_v4-rev0.7z'
  curl -fsS -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/5.3.0/threads-posix/sjlj/x86_64-5.3.0-release-posix-sjlj-rt_v4-rev0.7z'
  openssl dgst -sha256 pack.bin | grep -q ec28b6640ad4f183be7afcd6e9c5eabb24b89729ca3fec7618755555b5d70c19
  # Will unpack into "./mingw64"
  7z x -y pack.bin > /dev/null
  rm pack.bin

  # zlib
# curl -fsS -o pack.tar.gz -L --proto-redir =https "https://github.com/madler/zlib/archive/v${VER_ZLIB}.tar.gz"
# openssl dgst -sha256 pack.tar.gz | grep -q e380bd1bdb6447508beaa50efc653fe45f4edc1dafe11a251ae093e0ee97db9a
# tar -xvf pack.tar.gz > /dev/null 2>&1
# rm pack.tar.gz
# mv zlib-* zlib

  # nghttp2
  curl -fsS -o pack.tar.bz2 -L --proto-redir =https "https://github.com/tatsuhiro-t/nghttp2/releases/download/v${VER_NGHTTP2}/nghttp2-${VER_NGHTTP2}.tar.bz2"
  openssl dgst -sha256 pack.tar.bz2 | grep -q 7ac5624bc744c766bf6b37de31d7c48dfceb648313306311943968bdad77d5bd
  tar -xvf pack.tar.bz2 > /dev/null 2>&1
  rm pack.tar.bz2
  mv nghttp2-* nghttp2

  # openssl
  curl -fsS -o pack.tar.gz "https://www.openssl.org/source/openssl-${VER_OPENSSL}.tar.gz"
  openssl dgst -sha256 pack.tar.gz | grep -q e23ccafdb75cfcde782da0151731aa2185195ac745eea3846133f2e05c0e0bff
  tar -xvf pack.tar.gz > /dev/null 2>&1 || true
  rm pack.tar.gz
  mv openssl-* openssl

  # Create a fixed seed based on the timestamp of the OpenSSL source package
  sed -e "s/-frandom-seed=__RANDOM_SEED__/-frandom-seed=$(stat -c %Y openssl/CHANGES)/g" -i openssl.diff
  dos2unix < openssl.diff | patch -p1 -d openssl

  # librtmp
# curl -fsS -o pack.tar.gz "https://rtmpdump.mplayerhq.hu/download/rtmpdump-${VER_LIBRTMP}.tgz"
# openssl dgst -sha256 pack.tar.gz | grep -q ef38b7a99d82ce6912063d21063aeaf28185341b3df486e24bffce5354224b2c
# tar -xvf pack.tar.gz > /dev/null 2>&1
# rm pack.tar.gz
# mv rtmpdump-* librtmp

  # libssh2
  curl -fsS -o pack.tar.gz -L --proto-redir =https "https://github.com/libssh2/libssh2/releases/download/libssh2-${VER_LIBSSH2}/libssh2-${VER_LIBSSH2}.tar.gz"
  openssl dgst -sha256 pack.tar.gz | grep -q 5a202943a34a1d82a1c31f74094f2453c207bf9936093867f41414968c8e8215
  tar -xvf pack.tar.gz > /dev/null 2>&1
  rm pack.tar.gz
  mv libssh2-* libssh2
  dos2unix < libssh2.diff | patch -p1 -d libssh2

  # curl
  curl -fsS -o pack.tar.bz2 -L --proto-redir =https "https://github.com/bagder/curl/releases/download/curl-$(echo "${VER_CURL}" | sed -e 's|\.|_|g')/curl-${VER_CURL}.tar.bz2"
  openssl dgst -sha256 pack.tar.bz2 | grep -q b7d726cdd8ed4b6db0fa1b474a3c59ebbbe4dcd4c61ac5e7ade0e0270d3195ad
  tar -xvf pack.tar.bz2 > /dev/null 2>&1
  rm pack.tar.bz2
  mv curl-* curl
  dos2unix < curl.diff | patch -p1 -d curl
