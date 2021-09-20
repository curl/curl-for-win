#!/bin/sh -x

# Copyright 2015-present Viktor Szakats. See LICENSE.md

. ./_versions.sh

[ -z "${_REV}" ] || _REV="_${_REV}"

echo "Build: REV(${_REV})"

# Quit if any of the lines fail
set -e

# Install required component(s)
if [ "${_OS}" != 'win' ]; then
  pip3 --version
  pip3 --disable-pip-version-check --no-cache-dir install --user pefile
fi

alias curl='curl --disable --user-agent '' --fail --silent --show-error --connect-timeout 15 --max-time 20 --retry 3 --max-redirs 10'
alias gpg='gpg --batch --keyserver-options timeout=15 --keyid-format 0xlong'
[ "${_OS}" = 'mac' ] && alias tar='gtar'

gpg_recv_key() {
  # https://keys.openpgp.org/about/api
  req="pks/lookup?op=get&options=mr&exact=on&search=0x$1"
# curl "https://keys.openpgp.org/${req}"     | gpg --import --status-fd 1 || \
# curl "https://pgpkeys.eu/${req}"           | gpg --import --status-fd 1 || \
  curl "https://keyserver.ubuntu.com/${req}" | gpg --import --status-fd 1
}

gpg --version | grep -a -F gpg

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  _patsuf='.dev'
elif [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
  _patsuf='.test'
else
  _patsuf=''
fi

my_unpack() {
  pkg="$1"
  hash="$(openssl dgst -sha256 pkg.bin)"
  echo "${hash}"
  echo "${hash}" | grep -q -a -F "${2:-}" || exit 1
  rm -f -r "${pkg}" && mkdir "${pkg}" && tar --strip-components 1 -xf pkg.bin -C "${pkg}" || exit 1
  rm -f pkg.bin pkg.sig
  [ -f "${pkg}${_patsuf}.patch" ] && dos2unix < "${pkg}${_patsuf}.patch" | patch -N -p1 -d "${pkg}"
  return 0
}

if [ "${_BRANCH#*zlibng*}" != "${_BRANCH}" ]; then
  # zlib-ng
  curl --location --proto-redir =https \
    --output pkg.bin \
    "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/${ZLIBNG_VER_}.tar.gz" || exit 1
  my_unpack zlibng "${ZLIBNG_HASH}"
else
  # zlib
  curl \
    --output pkg.bin \
    "https://zlib.net/zlib-${ZLIB_VER_}.tar.xz" \
    --output pkg.sig \
    "https://zlib.net/zlib-${ZLIB_VER_}.tar.xz.asc" || exit 1
  gpg_recv_key 5ED46A6721D365587791E2AA783FCD8E58BCAFBA
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack zlib "${ZLIB_HASH}"
fi

# zstd
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://github.com/facebook/zstd/releases/download/v${ZSTD_VER_}/zstd-${ZSTD_VER_}.tar.zst" \
  --output pkg.sig \
  "https://github.com/facebook/zstd/releases/download/v${ZSTD_VER_}/zstd-${ZSTD_VER_}.tar.zst.sig" || exit 1
gpg_recv_key 4EF4AC63455FC9F4545D9B7DEF8FE99528B52FFD
gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
my_unpack zstd "${ZSTD_HASH}"

# brotli
# Relatively high curl binary size + extra dependency overhead aiming mostly
# to optimize webpage download sizes.
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://github.com/google/brotli/archive/v${BROTLI_VER_}.tar.gz" || exit 1
my_unpack brotli "${BROTLI_HASH}"

# nghttp2
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VER_}/nghttp2-${NGHTTP2_VER_}.tar.xz" || exit 1
my_unpack nghttp2 "${NGHTTP2_HASH}"

# libgsasl
curl \
  --output pkg.bin \
  "https://ftp.gnu.org/gnu/gsasl/libgsasl-${LIBGSASL_VER_}.tar.gz" \
  --output pkg.sig \
  "https://ftp.gnu.org/gnu/gsasl/libgsasl-${LIBGSASL_VER_}.tar.gz.sig" || exit 1
curl 'https://ftp.gnu.org/gnu/gnu-keyring.gpg' \
| gpg --quiet --import 2>/dev/null
gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
my_unpack libgsasl "${LIBGSASL_HASH}"

if [ "${_BRANCH#*winidn*}" = "${_BRANCH}" ]; then
  # libidn2
  curl \
    --output pkg.bin \
    "https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VER_}.tar.gz" \
    --output pkg.sig \
    "https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VER_}.tar.gz.sig" || exit 1
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack libidn2 "${LIBIDN2_HASH}"
fi

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ]; then
  # c-ares
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    CARES_VER_='1.17.2-dev'
    curl --location --proto-redir =https \
      --output pkg.bin \
      'https://github.com/c-ares/c-ares/archive/6ce842ff936116b8c1026ecaafdc06468af47e6c.tar.gz' || exit 1
    my_unpack c-ares
  else
    curl \
      --output pkg.bin \
      "https://c-ares.org/download/c-ares-${CARES_VER_}.tar.gz" \
      --output pkg.sig \
      "https://c-ares.org/download/c-ares-${CARES_VER_}.tar.gz.asc" || exit 1
    gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
    gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
    my_unpack c-ares "${CARES_HASH}"
  fi
fi

# openssl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  OPENSSL_VER_='3.0.0-beta2'
  OPENSSL_HASH=e76ab22879201b12f014393ee4becec7f264d8f6955b1036839128002868df71
fi
# QUIC fork:
#   https://github.com/quictls/openssl.git
curl \
  --output pkg.bin \
  "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz" \
  --output pkg.sig \
  "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz.asc" || exit 1
# Via:
#   https://www.openssl.org/community/omc.html
gpg_recv_key 8657ABB260F056B1E5190839D9C4D26D0E604491
gpg_recv_key 7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C
gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
my_unpack openssl "${OPENSSL_HASH}"

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.9.1-dev'
  curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/libssh2/libssh2/archive/a88a727c2a1840f979b34f12bcce3d55dcd7ea6e.tar.gz' || exit 1
  my_unpack libssh2
else
  curl \
    --output pkg.bin \
    "https://www.libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz" \
    --output pkg.sig \
    "https://www.libssh2.org/download/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack libssh2 "${LIBSSH2_HASH}"
fi

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.79.0-dev'
  curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/curl/curl/archive/5dc594e44f73b1726cabca6a4395323f972e416d.tar.gz' || exit 1
  my_unpack curl
else
  curl \
    --output pkg.bin \
    "https://curl.se/download/curl-${CURL_VER_}.tar.xz" \
    --output pkg.sig \
    "https://curl.se/download/curl-${CURL_VER_}.tar.xz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack curl "${CURL_HASH}"
fi

set +e
