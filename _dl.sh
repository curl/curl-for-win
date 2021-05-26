#!/bin/sh -x

# Copyright 2015-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

# Create revision string
# NOTE: Set _REV to empty after bumping CURL_VER_, and
#       set it to 1 then increment by 1 each time bumping a dependency
#       version or pushing a CI rebuild for the main branch.
export _REV='4'

export CURL_VER_='7.76.1'
export CURL_HASH=64bb5288c39f0840c07d077e30d9052e1cbb9fa6c2dc52523824cc859e679145
export LIBSSH2_VER_='1.9.0'
export LIBSSH2_HASH=d5fb8bd563305fd1074dda90bd053fb2d29fc4bce048d182f96eaa466dfadafd
export NGTCP2_VER_='0.1.90'
export NGTCP2_HASH=
export OPENSSL_VER_='1.1.1k'
export OPENSSL_HASH=892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5
export CARES_VER_='1.17.1'
export CARES_HASH=d73dd0f6de824afd407ce10750ea081af47eba52b8a6cb307d220131ad93fc40
export NGHTTP3_VER_='0.1.90'
export NGHTTP3_HASH=
export NGHTTP2_VER_='1.43.0'
export NGHTTP2_HASH=f7d54fa6f8aed29f695ca44612136fa2359013547394d5dffeffca9e01a26b0f
export LIBMETALINK_VER_='0.1.3'
export LIBMETALINK_HASH_=86312620c5b64c694b91f9cc355eabbd358fa92195b3e99517504076bf9fe33a
export EXPAT_VER_='2.4.1'
export EXPAT_HASH_=2f9b6a580b94577b150a7d5617ad4643a4301a6616ff459307df3e225bcfbf40
export LIBIDN2_VER_='2.3.1'
export LIBIDN2_HASH=8af684943836b8b53965d5f5b6714ef13c26c91eaa36ce7d242e3d21f5d40f2d
export LIBGSASL_VER_='1.10.0'
export LIBGSASL_HASH_=f1b553384dedbd87478449775546a358d6f5140c15cccc8fb574136fdc77329f
export BROTLI_VER_='1.0.9'
export BROTLI_HASH=f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46
export ZSTD_VER_='1.5.0'
export ZSTD_HASH=9aa8dfc1ca17f358b28988ca1f6e00ffe1c6f3198853f8d2022799e6f0669180
export ZLIBNG_VER_='2.0.3'
export ZLIBNG_HASH=30305bd1551e3454bddf574f9863caf7137dde0fdbd4dcd7094eacfbb23955a0
export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff

export OSSLSIGNCODE_VER_='2.1.0'
export OSSLSIGNCODE_HASH=c512931b6fe151297a1c689f88501e20ffc204c4ffe30e7392eb3decf195065b

[ -z "${_REV}" ] || _REV="_${_REV}"

echo "Build: REV(${_REV})"

# Quit if any of the lines fail
set -e

# Install required component(s)
if [ "${_OS}" != 'win' ]; then
  pip3 --version
  pip3 --disable-pip-version-check --no-cache-dir install --user pefile
fi

alias curl='curl --user-agent curl --fail --silent --show-error --connect-timeout 15 --max-time 20 --retry 3'
alias gpg='gpg --batch --keyserver-options timeout=15 --keyid-format long'
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
  openssl dgst -sha256 pkg.bin | grep -q -a -F "${2:-}" || exit 1
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
  my_unpack zlib-ng "${ZLIBNG_HASH}"
else
  # zlib
  curl --location --proto-redir =https \
    --output pkg.bin \
    "https://github.com/madler/zlib/archive/v${ZLIB_VER_}.tar.gz" || exit 1
  my_unpack zlib "${ZLIB_HASH}"
fi

# zstd
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://github.com/facebook/zstd/releases/download/v${ZSTD_VER_}/zstd-${ZSTD_VER_}.tar.zst" || exit 1
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

# expat
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://github.com/libexpat/libexpat/releases/download/R_$(echo "${EXPAT_VER_}" | tr '.' '_')/expat-${EXPAT_VER_}.tar.bz2" || exit 1
my_unpack expat "${EXPAT_HASH}"

# libmetalink
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://launchpad.net/libmetalink/trunk/libmetalink-${LIBMETALINK_VER_}/+download/libmetalink-${LIBMETALINK_VER_}.tar.xz" || exit 1
my_unpack libmetalink "${LIBMETALINK_HASH}"

if [ "${_BRANCH#*cares*}" != "${_BRANCH}" ]; then
  # c-ares
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    CARES_VER_='1.13.1-dev'
    curl --location --proto-redir =https \
      --output pkg.bin \
      'https://github.com/c-ares/c-ares/archive/611a5ef938c2ca92beb51f455323cda4d40119f7.tar.gz' || exit 1
    my_unpack cares
  else
    curl --location --proto-redir =https \
      --output pkg.bin \
      "https://github.com/c-ares/c-ares/releases/download/cares-$(echo "${CARES_VER_}" | tr '.' '_')/c-ares-${CARES_VER_}.tar.gz" \
      --output pkg.sig \
      "https://github.com/c-ares/c-ares/releases/download/cares-$(echo "${CARES_VER_}" | tr '.' '_')/c-ares-${CARES_VER_}.tar.gz.asc" || exit 1
    gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
    gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
    my_unpack cares "${CARES_HASH}"
  fi
fi

# openssl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  OPENSSL_VER_='1.1.1-pre1'
  curl --location --proto-redir =https \
    --output pkg.bin \
    'https://www.openssl.org/source/openssl-3.0.0-alpha9.tar.gz' || exit 1
  my_unpack openssl
else
  # QUIC fork:
  #   https://github.com/quictls/openssl.git
  curl \
    --output pkg.bin \
    "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz" \
    --output pkg.sig \
    "https://www.openssl.org/source/openssl-${OPENSSL_VER_}.tar.gz.asc" || exit 1
  # From:
  #   https://www.openssl.org/source/
  #   https://www.openssl.org/community/omc.html
  gpg_recv_key 8657ABB260F056B1E5190839D9C4D26D0E604491
  gpg_recv_key 7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack openssl "${OPENSSL_HASH}"
fi

# libssh2
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.9.1-dev'
  curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/libssh2/libssh2/archive/53ff2e6da450ac1801704b35b3360c9488161342.tar.gz' || exit 1
  my_unpack libssh2
else
  curl --location --proto-redir =https \
    --output pkg.bin \
    "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VER_}/libssh2-${LIBSSH2_VER_}.tar.gz" \
    --output pkg.sig \
    "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VER_}/libssh2-${LIBSSH2_VER_}.tar.gz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack libssh2 "${LIBSSH2_HASH}"
fi

# curl
if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.59.0-dev'
  curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/curl/curl/archive/63f6b3b22077c6fd4a75ce4ceac7258509af412c.tar.gz' || exit 1
  my_unpack curl
else
  curl --location --proto-redir =https \
    --output pkg.bin \
    "https://curl.se/download/curl-${CURL_VER_}.tar.xz" \
    --output pkg.sig \
    "https://curl.se/download/curl-${CURL_VER_}.tar.xz.asc" || exit 1
  gpg_recv_key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
  gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  my_unpack curl "${CURL_HASH}"
fi

# osslsigncode
curl --location --proto-redir =https \
  --output pkg.bin \
  "https://github.com/mtrojnar/osslsigncode/releases/download/2.1/osslsigncode-${OSSLSIGNCODE_VER_}.tar.gz" || exit 1
my_unpack osslsigncode "${OSSLSIGNCODE_HASH}"

set +e
