#!/usr/bin/env bash

# Copyright 2015-present Viktor Szakats. See LICENSE.md

set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

gpgdir="$(mktemp -d)"

meta() {
cat <<EOF
[
  {
    "name": "brotli",
    "url": "https://github.com/google/brotli/archive/v{ver}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "curl",
    "descending": true,
    "url": "https://curl.se/download/curl-{ver}.tar.xz",
    "sig": ".asc",
    "keys": "27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2"
  },
  {
    "name": "libgsasl",
    "url": "https://ftp.gnu.org/gnu/gsasl/libgsasl-{ver}.tar.gz",
    "sig": ".sig",
    "keys": "https://ftp.gnu.org/gnu/gnu-keyring.gpg"
  },
  {
    "name": "libidn2",
    "url": "https://ftp.gnu.org/gnu/libidn/libidn2-{ver}.tar.gz",
    "sig": ".sig",
    "keys": "https://ftp.gnu.org/gnu/gnu-keyring.gpg"
  },
  {
    "name": "libssh2",
    "url": "https://www.libssh2.org/download/libssh2-{ver}.tar.gz",
    "sig": ".asc",
    "keys": "27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2"
  },
  {
    "name": "nghttp2",
    "url": "https://github.com/nghttp2/nghttp2/releases/download/v{ver}/nghttp2-{ver}.tar.xz",
    "redir": "redir"
  },
  {
    "name": "openssl",
    "url": "https://www.openssl.org/source/openssl-{ver}.tar.gz",
    "sig": ".asc",
    "sha": ".sha256",
    "keys_comment": "Via: https://www.openssl.org/community/omc.html",
    "keys": "8657ABB260F056B1E5190839D9C4D26D0E604491 7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C"
  },
  {
    "name": "osslsigncode",
    "url": "https://github.com/mtrojnar/osslsigncode/releases/download/{vermm}/osslsigncode-{ver}.tar.gz",
    "sig": ".asc",
    "redir": "redir",
    "keys": "2BC7E4E67E3CC0C1BEA72F8C2EFC7FF0D416E014"
  },
  {
    "name": "zlib",
    "url": "https://zlib.net/zlib-{ver}.tar.xz",
    "sig": ".asc",
    "keys": "5ED46A6721D365587791E2AA783FCD8E58BCAFBA"
  },
  {
    "name": "zlibng",
    "url": "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/{ver}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "zstd",
    "url": "https://github.com/facebook/zstd/releases/download/v{ver}/zstd-{ver}.tar.zst",
    "sig": ".sig",
    "sha": ".sha256",
    "redir": "redir",
    "keys": "4EF4AC63455FC9F4545D9B7DEF8FE99528B52FFD"
  }
]
EOF
}

my_curl() {
  curl --disable --user-agent '' --fail --silent --show-error \
    --connect-timeout 15 --max-time 20 --retry 3 --max-redirs 10 "$@"
}

my_gpg() {
  gpg --homedir "${gpgdir}" --batch --keyserver-options timeout=15 --keyid-format 0xlong "$@"
}

gpg_recv_key() {
  local req
  req="pks/lookup?op=get&options=mr&exact=on&search=0x$1"
  my_curl "https://pgpkeys.eu/${req}"           | my_gpg --import --status-fd 1 || \
  my_curl "https://keyserver.ubuntu.com/${req}" | my_gpg --import --status-fd 1
}

# convert 'x.y.z' to zero-padded "0x0y0z" numeric format
to6digit() {
  local ver maj min rel
  ver="$(grep -a -o -E '[0-9]+\.[0-9]+\.[0-9]+')"
  maj="$(printf '%s' "${ver}" | grep -a -o -E '[0-9]+' | head -1)"
  min="$(printf '%s' "${ver}" | grep -a -o -E '[0-9]+' | head -2 | tail -1)"
  rel="$(printf '%s' "${ver}" | grep -a -o -E '[0-9]+' | tail -1)"
  printf '%02d%02d%02d' "${maj}" "${min}" "${rel}"
}

check_update() {
  local pkg url ourvern newver newvern slug mask urldir res
  pkg="$1"
  ourvern="${2:-000000}"
  url="$3"
  newver=''
  if [[ "${url}" =~ ^https://github.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)/ ]]; then
    slug="${BASH_REMATCH[1]}"
    # heavily rate-limited
    newver="$(my_curl --user-agent ' ' "https://api.github.com/repos/${slug}/releases/latest" | \
      jq -r '.tag_name' | sed -E 's|^v||')"
  else
    mask="${pkg}[._-]v?([0-9]+(\.[0-9]+)+)\.t"
    if [ "$4" = 'true' ]; then
      latest='head'
    else
      latest='tail'
    fi
    urldir="$(dirname "${url}")/"
    res="$(my_curl "${urldir}" | hxclean | hxselect -i -c -s '\n' 'a::attr(href)' | \
      grep -a -o -E -- "${mask}" | "${latest}" -1)"
    if [[ "${res}" =~ ${mask} ]]; then
      newver="${BASH_REMATCH[1]}"
    fi
  fi
  if [ -n "${newver}" ]; then
    newvern="$(printf '%s' "${newver}" | to6digit)"
    if [ "${newvern}" -gt "${ourvern}" ]; then
      printf '%s' "${newver}"
    fi
  fi
}

check_dl() {
  local name url keys sig sha options key ok hash_calc hash_got
  name="$1"
  url="$2"
  sig="$3"
  sha="$4"
  keys="$6"
  options=()
  [ "$5" = 'redir' ] && options+=(--location --proto-redir '=https')
  options+=(--output pkg.bin "${url}")
  [ -n "${sig}" ] && options+=(--output pkg.sig "${url}${sig}")
  [ -n "${sha}" ] && options+=(--output pkg.sha "${url}${sha}")
  my_curl "${options[@]}"

  ok='0'
  hash_calc="$(openssl dgst -sha256 pkg.bin | grep -a -i -o -E '[0-9a-f]{64}$')"
  if [ -n "${sig}" ]; then

    for key in ${keys}; do
      if [[ "${key}" = 'https://'* ]]; then
        my_curl --max-time 60 "${key}" | my_gpg --quiet --import >/dev/null 2>&1
      else
        gpg_recv_key "${key}" >/dev/null 2>&1
      fi
    done

    if my_gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin >/dev/null 2>&1; then
      >&2 echo "! ${name}: Verify: OK (Valid PGP signature)"
      if [ -n "${sha}" ]; then
        hash_got="$(grep -a -i -o -E '[0-9A-Fa-f]{64,}' pkg.sha | tr '[:upper:]' '[:lower:]')"
        if [ "${hash_calc}" = "${hash_got}" ]; then
          >&2 echo "! ${name}: Verify: OK (Matching hash)"
          ok='1'
        fi
      else
        ok='1'
      fi
    else
      >&2 echo "! ${name}: Verify: Failed (PGP signature)"
    fi
  else
    >&2 echo "! ${name}: Verify: No PGP signature. Continuing without verification."
    ok='1'
  fi

  if [ "${ok}" = '1' ]; then
    >&2 echo "! ${name}: New hash: |${hash_calc}|"
    printf '%s' "${hash_calc}"
  fi

  rm -f pkg.bin pkg.sig pkg.sha
}

bump() {
  local keypkg newcurl newdep pkg name ourver ourvern hashenv hash jp url desc pin
  local newver newhash sig sha redir keys urlver

  set +x

  keypkg='curl'

  newcurl=0
  newdep=0

  while read -r pkg; do
    if [[ "${pkg}" =~ ^([A-Z0-9]+)_VER_=(.+)$ ]]; then
      name="${BASH_REMATCH[1],,}"
      ourver="${BASH_REMATCH[2]}"
      ourvern="$(printf '%s' "${ourver}" | to6digit)"

      hashenv="${name^^}_HASH"
      eval hash="\$${hashenv}"

      jp="$(meta | jq \
        ".[] | select(.name == \"${name}\")")"

      newhash=''

      if [ -n "${jp}" ]; then
        url="$( printf '%s' "${jp}" | jq -r '.url')"
        desc="$(printf '%s' "${jp}" | jq -r '.descending')"
        pin="$( printf '%s' "${jp}" | jq -r '.pinned')"

        if [ "${pin}" = 'true' ]; then
          >&2 echo "! ${name}: Version pinned. Skipping."
        else
          newver="$(check_update "${name}" "${ourvern}" "${url}" "${desc}")"
          if [ -n "${newver}" ]; then
            >&2 echo "! ${name}: New version found: |${newver}|"

            sig="$(  printf '%s' "${jp}" | jq -r '.sig' | sed -E 's|^null$||g')"
            sha="$(  printf '%s' "${jp}" | jq -r '.sha' | sed -E 's|^null$||g')"
            redir="$(printf '%s' "${jp}" | jq -r '.redir')"
            keys="$( printf '%s' "${jp}" | jq -r '.keys' | sed -E 's|^null$||g')"

            urlver="$(printf '%s' "${url}" | sed \
                -e "s|{ver}|${newver}|g" \
                -e "s|{vermm}|$(echo "${newver}" | cut -d . -f -2)|g" \
              )"
            newhash="$(check_dl "${name}" "${urlver}" "${sig}" "${sha}" "${redir}" "${keys}")"
            if [ -z "${newhash}" ]; then
              >&2 echo "! ${name}: New version failed to validate."
            elif [ "${name}" == "${keypkg}" ]; then
              newcurl=1
            else
              newdep=1
            fi
          fi
        fi
      else
        >&2 echo "! ${name}: Metadata not found. Skipping."
      fi

      if [ -z "${newhash}" ]; then
        # Keep old values
        newver="${ourver}"
        # shellcheck disable=SC2154
        newhash="${hash}"
      fi

      echo "export ${name^^}_VER_='${newver}'"
      echo "export ${hashenv}=${newhash}"
    fi
  done <<< "$(env | grep -a -E '^[A-Z0-9]+_VER_' | \
    sed -E "s|^${keypkg}|0X0X|g" | sort | \
    sed -E "s|^0X0X|${keypkg}|g")"

  if [ "${newcurl}" = '1' ]; then
    _REVN=''  # Reset revision on each curl version bump
  elif [ "${newdep}" = '1' ]; then
    ((_REVN+=1))  # Bump revision with each dependency version bump
  fi

  echo "export _REVN=${_REVN}"
}

if [ "${1:-}" = 'bump' ]; then
  bump
  rm -r -f "${gpgdir}"
  exit
fi

# shellcheck disable=SC2153
echo "Build: REV(${_REV})"

# Quit if any of the lines fail
set -e

# Install required component(s)
if [ "${_OS}" != 'win' ]; then
  pip3 --version
  pip3 --disable-pip-version-check --no-cache-dir install --user pefile
fi

if [ "${_OS}" = 'mac' ]; then
  tar() { gtar "$@"; }
fi

my_gpg --version | grep -a -F gpg

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  _patsuf='.dev'
elif [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
  _patsuf='.test'
else
  _patsuf=''
fi

live_xt() {
  local pkg hash
  pkg="$1"
  hash="$(openssl dgst -sha256 pkg.bin)"
  echo "${hash}"
  echo "${hash}" | grep -q -a -F -- "${2:-}" || exit 1
  rm -f -r "${pkg}"; mkdir "${pkg}"; tar --strip-components 1 -xf pkg.bin -C "${pkg}"
  rm -f pkg.bin pkg.sig
  [ -f "${pkg}${_patsuf}.patch" ] && dos2unix < "${pkg}${_patsuf}.patch" | patch -N -p1 -d "${pkg}"
  return 0
}

live_dl() {
  local name ver hash jp url sig redir key keys options

  name="$1"
  ver="$2"
  hash="${3:-}"

  set +x
  jp="$(meta | jq \
    ".[] | select(.name == \"${name}\")")"

  url="$(  printf '%s' "${jp}" | jq -r '.url' | sed \
      -e "s|{ver}|${ver}|g" \
      -e "s|{vermm}|$(echo "${ver}" | cut -d . -f -2)|g" \
    )"
  sig="$(  printf '%s' "${jp}" | jq -r '.sig' | sed -E 's|^null$||g')"
  redir="$(printf '%s' "${jp}" | jq -r '.redir')"
  keys="$( printf '%s' "${jp}" | jq -r '.keys' | sed -E 's|^null$||g')"

  options=()
  [ "${redir}" = 'redir' ] && options+=(--location --proto-redir '=https')
  options+=(--output pkg.bin "${url}")
  [ -n "${sig}" ] && options+=(--output pkg.sig "${url}${sig}")
  set -x
  my_curl "${options[@]}"

  if [ -n "${sig}" ]; then
    for key in ${keys}; do
      if printf '%s' "${key}" | grep -q -a '^https://'; then
        # gnu-keyring.gpg can take a long time to import, so allow curl to
        # run longer.
        my_curl --max-time 60 "${key}" | my_gpg --quiet --import 2>/dev/null
      else
        gpg_recv_key "${key}"
      fi
    done
    my_gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
  fi

  if [ -n "${hash}" ]; then
    live_xt "${name}" "${hash}"
  else
    true
  fi
}

if [ "${_BRANCH#*zlibng*}" != "${_BRANCH}" ]; then
  live_dl zlibng "${ZLIBNG_VER_}"
  live_xt zlibng "${ZLIBNG_HASH}"
else
  live_dl zlib "${ZLIB_VER_}"
  live_xt zlib "${ZLIB_HASH}"
fi

if [ "${_BRANCH#*mini*}" = "${_BRANCH}" ]; then
  live_dl zstd "${ZSTD_VER_}"
  live_xt zstd "${ZSTD_HASH}"

  live_dl brotli "${BROTLI_VER_}"
  live_xt brotli "${BROTLI_HASH}"
fi

live_dl nghttp2 "${NGHTTP2_VER_}"
live_xt nghttp2 "${NGHTTP2_HASH}"

live_dl libgsasl "${LIBGSASL_VER_}"
live_xt libgsasl "${LIBGSASL_HASH}"

if [ "${_BRANCH#*mini*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*winidn*}" = "${_BRANCH}" ]; then
  live_dl libidn2 "${LIBIDN2_VER_}"
  live_xt libidn2 "${LIBIDN2_HASH}"
fi

if [ "${_BRANCH#*mini*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*schannel*}" = "${_BRANCH}" ]; then
  # QUIC fork: https://github.com/quictls/openssl.git
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    OPENSSL_VER_='3.0.0-beta2'
    OPENSSL_HASH=e76ab22879201b12f014393ee4becec7f264d8f6955b1036839128002868df71
  fi
  live_dl openssl "${OPENSSL_VER_}"
  live_xt openssl "${OPENSSL_HASH}"
fi

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  LIBSSH2_VER_='1.9.1-dev'
  LIBSSH2_HASH=
  my_curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/libssh2/libssh2/archive/a88a727c2a1840f979b34f12bcce3d55dcd7ea6e.tar.gz'
else
  live_dl libssh2 "${LIBSSH2_VER_}"
fi
live_xt libssh2 "${LIBSSH2_HASH}"

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.79.0-dev'
  CURL_HASH=
  my_curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/curl/curl/archive/5dc594e44f73b1726cabca6a4395323f972e416d.tar.gz'
else
  live_dl curl "${CURL_VER_}"
fi
live_xt curl "${CURL_HASH}"

live_dl osslsigncode "${OSSLSIGNCODE_VER_}"
live_xt osslsigncode "${OSSLSIGNCODE_HASH}"

rm -r -f "${gpgdir}"
