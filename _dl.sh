#!/bin/sh -x

# Copyright 2015-2016 Viktor Szakats (vszakats.net/harbour)
# See LICENSE.md

export ZLIB_VER_='1.2.8'
export ZLIB_HASH=e380bd1bdb6447508beaa50efc653fe45f4edc1dafe11a251ae093e0ee97db9a
export LIBIDN_VER_='1.32'
export LIBIDN_HASH=ba5d5afee2beff703a34ee094668da5c6ea5afa38784cebba8924105e185c4f5
export NGHTTP2_VER_='1.9.2'
export NGHTTP2_HASH=8029e0d1bfe0f07ba350ebf585eec11d397252f4edfeb571e36c1c572bd0d5ca
export CARES_VER_='1.11.0'
export CARES_HASH=b3612e6617d9682928a1d50c1040de4db6519f977f0b25d40cf1b632900b3efd
export LIBRESSL_VER_='2.3.3'
export LIBRESSL_HASH=76733166187cc8587e0ebe1e83965ef257262a1a676a36806edd3b6d51b50aa9
export OPENSSL_VER_='1.0.2g'
export OPENSSL_HASH=b784b1b3907ce39abf4098702dade6365522a253ad1552e267a9a0e89594aa33
export LIBRTMP_VER_='2.4+20151223'
export LIBRTMP_HASH=f8eb8d0c8ed085c90666ba0e8fbe0e960e0cf0c2a58604fda3ed85a28f2ef5f6
export LIBSSH2_VER_='1.7.0'
export LIBSSH2_HASH=e4561fd43a50539a8c2ceb37841691baf03ecb7daf043766da1b112e4280d584
export CURL_VER_='7.48.0'
export CURL_HASH=864e7819210b586d42c674a1fdd577ce75a78b3dda64c63565abe5aefd72c753

# Quit if any of the lines fail
set -e

# Install required component
python -m pip --disable-pip-version-check install --upgrade pip
python -m pip install pefile

alias curl='curl -fsS --connect-timeout 15'
alias gpg='gpg --keyid-format LONG'

gpg --version | grep gpg

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   _patsuf='.dev'
else
   _patsuf=''
fi

if [ "${_BRANCH#*msysmingw*}" = "${_BRANCH}" ] ; then
   # mingw
   curl -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/5.3.0/threads-posix/sjlj/x86_64-5.3.0-release-posix-sjlj-rt_v4-rev0.7z' || exit 1
   openssl dgst -sha256 pack.bin | grep -q ec28b6640ad4f183be7afcd6e9c5eabb24b89729ca3fec7618755555b5d70c19 || exit 1
   # Will unpack into './mingw64'
   7z x -y pack.bin > /dev/null || exit 1
   rm pack.bin
fi

# nghttp2
curl -o pack.bin -L --proto-redir =https "https://github.com/tatsuhiro-t/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.bz2" || exit 1
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
   gpg --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBIDN_HASH}" || exit 1
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r libidn && mv libidn-* libidn
fi

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ] ; then
   # c-ares
   if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
      CARES_VER_='1.11.1-dev'
      curl -o pack.bin -L --proto-redir =https https://github.com/c-ares/c-ares/archive/0b7a497ab7f1d2f84bc3c6df0badd0d311fbb6c6.tar.gz || exit 1
   else
      curl -o pack.bin "http://c-ares.haxx.se/download/c-ares-${CARES_VER_}.tar.gz" || exit 1
      curl -o pack.sig "http://c-ares.haxx.se/download/c-ares-${CARES_VER_}.tar.gz.asc" || exit 1
      gpg -q --keyserver hkps://pgp.mit.edu --recv-keys 78E11C6B279D5C91
      gpg --verify pack.sig pack.bin || exit 1
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
   gpg -q --keyserver hkps://pgp.mit.edu --recv-keys 663AF51BD5E4D8D5
   gpg --verify pack.sig pack.bin || exit 1
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
      gpg -q --keyserver hkps://pgp.mit.edu --recv-keys D9C4D26D0E604491 D3577507FA40E9E2 9195C48241FBF7DD DFAB592ABDD52F1C 2064C53641C25E5D F23479455C51B27C 0833F510E18C1C32
      gpg --verify pack.sig pack.bin || exit 1
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
   curl -o pack.bin 'https://mirrorservice.org/sites/ftp.debian.org/debian/pool/main/r/rtmpdump/rtmpdump_2.4+20151223.gitfa8646d.orig.tar.gz' || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBRTMP_HASH}" || exit 1
   tar -xvf pack.bin > /dev/null 2>&1 || exit 1
   rm pack.bin
   rm -f -r librtmp && mv rtmpdump-* librtmp
fi

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   LIBSSH2_VER_='1.7.1-dev'
   curl -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/1fcf849e15ffda99cc30b6d23b8d378f501225a2.tar.gz || exit 1
else
   curl -o pack.bin -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz" || exit 1
   curl -o pack.sig -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
   gpg -q --keyserver hkps://pgp.mit.edu --recv-keys 78E11C6B279D5C91
   gpg --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${LIBSSH2_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r libssh2 && mv libssh2-* libssh2
[ -f "libssh2${_patsuf}.diff" ] && dos2unix < "libssh2${_patsuf}.diff" | patch -N -p1 -d libssh2

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ] ; then
   CURL_VER_='7.47.2-dev'
   curl -o pack.bin -L --proto-redir =https https://github.com/curl/curl/archive/71398487e75e47c026d0655d540ade247d18f62c.tar.gz || exit 1
else
   curl -o pack.bin "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2" || exit 1
   curl -o pack.sig "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.bz2.asc" || exit 1
   gpg -q --keyserver hkps://pgp.mit.edu --recv-keys 78E11C6B279D5C91
   gpg --verify pack.sig pack.bin || exit 1
   openssl dgst -sha256 pack.bin | grep -q "${CURL_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r curl && mv curl-* curl
[ -f "curl${_patsuf}.diff" ] && dos2unix < "curl${_patsuf}.diff" | patch -N -p1 -d curl

set +e
