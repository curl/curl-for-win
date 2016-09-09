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
export OPENSSL_VER_='1.1.0'
export OPENSSL_HASH=f5c69ff9ac1472c80b868efc1c1c0d8dcfc746d29ebe563de2365dd56dbd8c82
export LIBRTMP_VER_='2.4+20151223'
export LIBRTMP_HASH=5c032f5c8cc2937eb55a81a94effdfed3b0a0304b6376147b86f951e225e3ab5
export LIBSSH2_VER_='1.7.0'
export LIBSSH2_HASH=e4561fd43a50539a8c2ceb37841691baf03ecb7daf043766da1b112e4280d584
export CURL_VER_='7.50.2'
export CURL_HASH=0c72105df4e9575d68bcf43aea1751056c1d29b1040df6194a49c5ac08f8e233

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
   curl -o pack.bin -L 'https://downloads.sourceforge.net/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/6.2.0/threads-posix/sjlj/x86_64-6.2.0-release-posix-sjlj-rt_v5-rev1.7z' || exit 1
   openssl dgst -sha256 pack.bin | grep -q b7a06b84b3e55566e15239d672da01109a055a1c66ee2cccec5b084233c767b2 || exit 1
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
   # Patch allowing to disable tests using the no-tests Configure option
   curl -o openssl.diff -L --proto-redir =https https://github.com/openssl/openssl/pull/1514.diff
   openssl dgst -sha256 openssl.diff | grep -q d2d0d529e94ed7737007d59f547bd073e164dc6c46aa915f5d713152b51f7d46 || exit 1
   [ -f "openssl${_patsuf}.diff" ] && dos2unix < "openssl${_patsuf}.diff" | patch -N -p1 -d openssl
   # Patch to fix a recurring regression regarding some macros
   curl -o openssl.diff -L --proto-redir =https https://github.com/openssl/openssl/pull/1520.diff
   openssl dgst -sha256 openssl.diff | grep -q d7cbd46bf6bc0a72ced56b24e93bf616fc1ec8f6b7f25ec1d2fb3d661ad2eef5 || exit 1
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
# Patch to make libssh2 compatible with OpenSSL 1.1.0. Remove in next version.
curl -o libssh2.diff -L --proto-redir =https https://github.com/libssh2/libssh2/commit/64ebfd8182a9b6e637e65c3059e3798e199274b3.diff
openssl dgst -sha256 libssh2.diff | grep -q 548f5b5f743f9fd30d8748acf9282a56ed3641f6a6c334010597112b7dadbb65 || exit 1
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
