#!/bin/sh -x

# Copyright 2015-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

# Create revision string
# NOTE: Set _REV to empty after bumping CURL_VER_, and
#       set it to 1 then increment by 1 each time bumping a dependency
#       version or pushing a CI rebuild for the main branch.
export _REV='2'

export CURL_VER_='7.78.0'
export CURL_HASH=be42766d5664a739c3974ee3dfbbcbe978a4ccb1fe628bb1d9b59ac79e445fb5
export LIBSSH2_VER_='1.9.0'
export LIBSSH2_HASH=d5fb8bd563305fd1074dda90bd053fb2d29fc4bce048d182f96eaa466dfadafd
export NGTCP2_VER_='0.1.90'
export NGTCP2_HASH=
export OPENSSL_VER_='1.1.1l'
export OPENSSL_HASH=0b7a3e5e59c34827fe0c3a74b7ec8baef302b98fa80088d7f9153aa16fa76bd1
export CARES_VER_='1.17.1'
export CARES_HASH=d73dd0f6de824afd407ce10750ea081af47eba52b8a6cb307d220131ad93fc40
export NGHTTP3_VER_='0.1.90'
export NGHTTP3_HASH=
export NGHTTP2_VER_='1.44.0'
export NGHTTP2_HASH=5699473b29941e8dafed10de5c8cb37a3581edf62ba7d04b911ca247d4de3c5d
export LIBIDN2_VER_='2.3.2'
export LIBIDN2_HASH=76940cd4e778e8093579a9d195b25fff5e936e9dc6242068528b437a76764f91
export LIBGSASL_VER_='1.10.0'
export LIBGSASL_HASH=f1b553384dedbd87478449775546a358d6f5140c15cccc8fb574136fdc77329f
export BROTLI_VER_='1.0.9'
export BROTLI_HASH=f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46
export ZSTD_VER_='1.5.0'
export ZSTD_HASH=9aa8dfc1ca17f358b28988ca1f6e00ffe1c6f3198853f8d2022799e6f0669180
export ZLIBNG_VER_='2.0.5'
export ZLIBNG_HASH=eca3fe72aea7036c31d00ca120493923c4d5b99fe02e6d3322f7c88dbdcd0085
export ZLIB_VER_='1.2.11'
export ZLIB_HASH=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff

export OSSLSIGNCODE_VER_='2.2.0'
export OSSLSIGNCODE_HASH=51694331952b3e8b3b20d5de155c6bedb286583c6863ab4bd679c3f288c9b8d1

[ -z "${_REV}" ] || _REV="_${_REV}"

echo "Build: REV(${_REV})"

# Quit if any of the lines fail
set -e

# Install required component(s)
if [ "${_OS}" != 'win' ]; then
  pip3 --version
  pip3 --disable-pip-version-check --no-cache-dir install --user pefile
fi

alias curl='curl --user-agent curl --fail --silent --show-error --connect-timeout 15 --max-time 20 --retry 3 --max-redirs 10'
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
[ "${_BRANCH#*dev*}" != "${_BRANCH}" ] && OPENSSL_VER_='3.0.0-alpha9'
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
  "https://github.com/mtrojnar/osslsigncode/releases/download/$(echo "${OSSLSIGNCODE_VER_}" | cut -d . -f -2)/osslsigncode-${OSSLSIGNCODE_VER_}.tar.gz" || exit 1
my_unpack osslsigncode "${OSSLSIGNCODE_HASH}"

set +e
