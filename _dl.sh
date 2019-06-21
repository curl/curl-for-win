#!/bin/sh -x

# Copyright 2015-2019 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff
export LIBHSTS_VER_='0.1.0'
export LIBHSTS_HASH=e1125e0395b4777361eafafd61fff2b516d3f2fb57d56e40cb554a6cd8c024e0
export BROTLI_VER_='1.0.7'
export BROTLI_HASH=4c61bfb0faca87219ea587326c467b95acb25555b53d1a421ffa3c8a9296ee2c
export LIBIDN2_VER_='2.0.5'
export LIBIDN2_HASH=53f69170886f1fa6fa5b332439c7a77a7d22626a82ef17e2c1224858bb4ca2b8
export NGHTTP2_VER_='1.39.1'
export NGHTTP2_HASH=679160766401f474731fd60c3aca095f88451e3cc4709b72306e4c34cf981448
export CARES_VER_='1.15.0'
export CARES_HASH=6cdb97871f2930530c97deb7cf5c8fa4be5a0b02c7cea6e7c7667672a39d6852
export OPENSSL_VER_='1.1.1c'
export OPENSSL_HASH=f6fb3079ad15076154eda9413fed42877d668e7069d9b87396d0804fdb3f4c90
export LIBSSH2_VER_='1.9.0'
export LIBSSH2_HASH=d5fb8bd563305fd1074dda90bd053fb2d29fc4bce048d182f96eaa466dfadafd
export CURL_VER_='7.65.1'
export CURL_HASH=f6c22074877f235aebc7c53057dbc7ee82358f8ae58bfb767e955c18c859a77a
export OSSLSIGNCODE_VER_='1.7.1'
export OSSLSIGNCODE_HASH=f9a8cdb38b9c309326764ebc937cba1523a3a751a7ab05df3ecc99d18ae466c9

# Create revision string
# NOTE: Set _REV to empty after bumping CURL_VER_, and
#       set it to 1 then increment by 1 each time bumping a dependency
#       version or pushing a CI rebuild for the master branch.
export _REV='3'

[ -z "${_REV}" ] || _REV="_${_REV}"

echo "Build: REV(${_REV})"

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
# TODO: add `--progress-bar off` when pip 10.0.0 is available
if [ "${os}" != 'win' ]; then
  pip3 --version
  pip3 --disable-pip-version-check install --user pefile
fi

alias curl='curl -fsS --connect-timeout 15 -m 20 --retry 3'
alias gpg='gpg --batch --keyserver-options timeout=15 --keyid-format LONG'

gpg_recv_key() {
  req="pks/lookup?search=0x$1&op=get"
  curl "https://pgp.mit.edu/${req}"          | gpg --import --status-fd 1 || \
  curl "https://pgpkeys.eu/${req}"           | gpg --import --status-fd 1 || \
  curl "https://keyserver.ubuntu.com/${req}" | gpg --import --status-fd 1
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
    gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
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
  # From:
  #   https://www.openssl.org/source/
  #   https://www.openssl.org/community/omc.html
  gpg_recv_key 8657ABB260F056B1E5190839D9C4D26D0E604491
  gpg_recv_key 7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${OPENSSL_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r openssl && mv openssl-* openssl
[ -f "openssl${_patsuf}.patch" ] && dos2unix < "openssl${_patsuf}.patch" | patch --batch -N -p1 -d openssl

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.9.1-dev'
  curl -o pack.bin -L --proto-redir =https https://github.com/libssh2/libssh2/archive/53ff2e6da450ac1801704b35b3360c9488161342.tar.gz || exit 1
else
  curl \
    -o pack.bin -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz" \
    -o pack.sig -L --proto-redir =https "https://libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
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
    -o pack.sig "https://curl.haxx.se/download/curl-${CURL_VER_}.tar.xz.asc" || \
  curl \
    -o pack.bin -L --proto-redir =https "https://github.com/curl/curl/releases/download/curl-$(echo "${CURL_VER_}" | tr '.' '_')/curl-${CURL_VER_}.tar.xz" \
    -o pack.sig -L --proto-redir =https "https://github.com/curl/curl/releases/download/curl-$(echo "${CURL_VER_}" | tr '.' '_')/curl-${CURL_VER_}.tar.xz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pack.sig pack.bin || exit 1
  openssl dgst -sha256 pack.bin | grep -q "${CURL_HASH}" || exit 1
fi
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r curl && mv curl-* curl
[ -f "curl${_patsuf}.patch" ] && dos2unix < "curl${_patsuf}.patch" | patch --batch -N -p1 -d curl

# libhsts
curl \
  -o pack.bin "https://gitlab.com/rockdaboot/libhsts/uploads/4753f61b5a3c6253acf4934217816e3f/libhsts-${LIBHSTS_VER_}.tar.gz" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${LIBHSTS_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r libhsts && mv libhsts-* libhsts
[ -f "libhsts${_patsuf}.patch" ] && dos2unix < "libhsts${_patsuf}.patch" | patch --batch -N -p1 -d libhsts

# osslsigncode
curl -o pack.bin -L --proto-redir =https "https://deb.debian.org/debian/pool/main/o/osslsigncode/osslsigncode_${OSSLSIGNCODE_VER_}.orig.tar.gz" || exit 1
openssl dgst -sha256 pack.bin | grep -q "${OSSLSIGNCODE_HASH}" || exit 1
tar -xvf pack.bin > /dev/null 2>&1 || exit 1
rm pack.bin
rm -f -r osslsigncode && mv osslsigncode-* osslsigncode
[ -f 'osslsigncode.patch' ] && dos2unix < 'osslsigncode.patch' | patch --batch -N -p1 -d osslsigncode

set +e

rm -f pack.bin pack.sig
