#!/usr/bin/env bash

# Copyright 2015-present Viktor Szakats. See LICENSE.md

set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

gpgdir="$(mktemp -d)"

dependencies_json() {
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
    "name": "nghttp3",
    "url": "https://github.com/ngtcp2/nghttp3/releases/download/v{ver}/nghttp3-{ver}.tar.xz",
    "redir": "redir",
    "tag": ".+"
  },
  {
    "name": "ngtcp2",
    "url": "https://github.com/ngtcp2/ngtcp2/releases/download/v{ver}/ngtcp2-{ver}.tar.xz",
    "redir": "redir",
    "tag": ".+"
  },
  {
    "name": "openssl-quic",
    "url": "https://github.com/quictls/openssl/archive/refs/heads/openssl-{ver}+quic.tar.gz",
    "redir": "redir",
    "tag": "openssl-\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\+quic$",
    "hasfile": "README-OpenSSL.md"
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
    "name": "libressl",
    "url": "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-{ver}.tar.gz",
    "sig": ".asc",
    "keys": "A1EB079B8D3EB92B4EBD3139663AF51BD5E4D8D5"
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
    "name": "pefile",
    "url": "https://github.com/erocarrera/pefile/releases/download/v{ver}/pefile-{ver}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "llvm-mingw-linux",
    "url": "https://github.com/mstorsjo/llvm-mingw/releases/download/{ver}/llvm-mingw-{ver}-ucrt-ubuntu-18.04-x86_64.tar.xz",
    "redir": "redir"
  },
  {
    "name": "llvm-mingw-mac",
    "url": "https://github.com/mstorsjo/llvm-mingw/releases/download/{ver}/llvm-mingw-{ver}-ucrt-macos-universal.tar.xz",
    "redir": "redir"
  },
  {
    "name": "llvm-mingw-win",
    "url": "https://github.com/mstorsjo/llvm-mingw/releases/download/{ver}/llvm-mingw-{ver}-ucrt-x86_64.zip",
    "redir": "redir"
  }
]
EOF
}

my_curl() {
  # >&2 echo "|$@|"
  curl --disable --user-agent '' --fail --silent --show-error \
    --connect-timeout 15 --max-time 60 --retry 3 --max-redirs 10 "$@"
}

my_gpg() {
  local opts
  opts=()
  if [ -z "${APPVEYOR_REPO_BRANCH:-}${CI_COMMIT_REF_NAME:-}${GITHUB_REF:-}" ]; then
    # Do not populate user GPG configuration with build-related keys, unless
    # this is an automated CI session, where this is fine. In CI environments,
    # as of gnupg 2.2.27, using --homedir or GNUPGHOME causes frequent
    # intermittent fatal errors on later symmetric-key gpg calls that
    # do not use a homedir override.
    opts+=(--homedir "${gpgdir}")
  fi
  gpg "${opts[@]}" --batch --keyserver-options timeout=15 --keyid-format 0xlong "$@"
}

gpg_recv_key() {
  local req
  req="pks/lookup?op=get&options=mr&exact=on&search=0x$1"
  my_curl "https://pgpkeys.eu/${req}"           | my_gpg --import --status-fd 1 || \
  my_curl "https://keyserver.ubuntu.com/${req}" | my_gpg --import --status-fd 1
}

# convert 'x.y.z' to zero-padded "000x0y0z" numeric format (or leave as-is)
to8digit() {
  local ver maj min rel
  ver="$(cat)"
  if [[ "${ver}" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    maj="${BASH_REMATCH[1]}"
    min="${BASH_REMATCH[2]}"
    rel="${BASH_REMATCH[3]}"
    printf '%04d%02d%02d' "${maj}" "${min}" "${rel}"
  else
    printf '%s' "${ver}"
  fi
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
    if [ -n "$5" ]; then
      ref="$(my_curl --user-agent ' ' "https://api.github.com/repos/${slug}/git/refs/heads" \
        | jq --raw-output '.[].ref' \
        | grep -a -E "$5" | sort | tail -1)"
      newver="$(printf '%s' "${ref}" | grep -a -E -o '\d+\.\d+\.\d')"
      # Optionally, check for the presence of a path
      if [ -n "$6" ] && \
         ! my_curl --head "https://raw.githubusercontent.com/${slug}/${ref}/$6" >/dev/null 2>&1; then
        newver=''
      fi
    else
      newver="$(my_curl --user-agent ' ' "https://api.github.com/repos/${slug}/releases/latest" \
        | jq --raw-output '.tag_name' | sed 's/^v//')"
      if [[ "${newver}" =~ ^[0-9]+\.[0-9]+$ ]]; then
        newver="${newver}.0"
      fi
    fi
  else
    mask="${pkg}[._-]v?([0-9]+(\.[0-9]+)+)\.t"
    if [ "$4" = 'true' ]; then
      latest='head'
    else
      latest='tail'
    fi
    urldir="$(dirname "${url}")/"
    res="$(my_curl "${urldir}" | hxclean | hxselect -i -c -s '\n' 'a::attr(href)' \
      | grep -a -o -E -- "${mask}" | "${latest}" -1)"
    if [[ "${res}" =~ ${mask} ]]; then
      newver="${BASH_REMATCH[1]}"
    fi
  fi
  if [ -n "${newver}" ]; then
    newvern="$(printf '%s' "${newver}" | to8digit)"
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
    if [[ "${pkg}" =~ ^([A-Z0-9_]+)_VER_=(.+)$ ]]; then
      nameenv="${BASH_REMATCH[1]}"
      name="${nameenv,,}"
      name="${name//_/-}"
      ourver="${BASH_REMATCH[2]}"
      ourvern="$(printf '%s' "${ourver}" | to8digit)"

      hashenv="${nameenv}_HASH"
      eval hash="\${${hashenv}:-}"

      jp="$(dependencies_json | jq \
        ".[] | select(.name == \"${name}\")")"

      newhash=''

      if [ -n "${jp}" ]; then
        url="$(     printf '%s' "${jp}" | jq --raw-output '.url')"
        desc="$(    printf '%s' "${jp}" | jq --raw-output '.descending')"
        pin="$(     printf '%s' "${jp}" | jq --raw-output '.pinned')"
        tag="$(     printf '%s' "${jp}" | jq --raw-output '.tag' | sed 's/^null$//')"
        hasfile="$( printf '%s' "${jp}" | jq --raw-output '.hasfile' | sed 's/^null$//')"

        if [ "${pin}" = 'true' ]; then
          >&2 echo "! ${name}: Version pinned. Skipping."
        else
          newver="$(check_update "${name}" "${ourvern}" "${url}" "${desc}" "${tag}" "${hasfile}")"
          if [ -n "${newver}" ]; then
            >&2 echo "! ${name}: New version found: |${newver}|"

            if [ -n "${hash}" ]; then
              sig="$(  printf '%s' "${jp}" | jq --raw-output '.sig' | sed 's/^null$//')"
              sha="$(  printf '%s' "${jp}" | jq --raw-output '.sha' | sed 's/^null$//')"
              redir="$(printf '%s' "${jp}" | jq --raw-output '.redir')"
              keys="$( printf '%s' "${jp}" | jq --raw-output '.keys' | sed 's/^null$//')"

              urlver="$(printf '%s' "${url}" | sed \
                  -e "s/{ver}/${newver}/g" \
                  -e "s/{vermm}/$(echo "${newver}" | cut -d . -f -2)/g" \
                )"
              newhash="$(check_dl "${name}" "${urlver}" "${sig}" "${sha}" "${redir}" "${keys}")"
            else
              newhash='-'
            fi

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
        >&2 echo "! ${name}: Dependency metadata not found. Skipping."
      fi

      if [ -z "${newhash}" ]; then
        # Keep old values
        newver="${ourver}"
        # shellcheck disable=SC2154
        newhash="${hash}"
      fi

      echo "export ${nameenv^^}_VER_='${newver}'"
      [ -n "${hash}" ] && echo "export ${hashenv}=${newhash}"
    fi
  done <<< "$(env | grep -a -E '^[A-Z0-9_]+_VER_' | \
    sed "s/^${keypkg}/0X0X/g" | sort | \
    sed "s/^0X0X/${keypkg}/g")"

  if [ "${newcurl}" = '1' ]; then
    _REV=''  # Reset revision on each curl version bump
  elif [ "${newdep}" = '1' ]; then
    ((_REV+=1))  # Bump revision with each dependency version bump
  fi

  echo "export _REV=${_REV}"
}

if [ "${1:-}" = 'bump' ]; then
  bump
  rm -r -f "${gpgdir}"
  exit
fi

echo "Build: REV(${_REVSUFFIX})"

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
  if [ -z "${CW_GET:-}" ] || echo "${CW_GET}" | grep -q -F "${pkg}"; then
    hash="$(openssl dgst -sha256 pkg.bin)"
    echo "${hash}"
    echo "${hash}" | grep -q -a -F -- "${2:-}" || exit 1
    rm -f -r "${pkg}"; mkdir "${pkg}"; tar --strip-components 1 -xf pkg.bin -C "${pkg}"
    rm -f pkg.bin pkg.sig
    [ -f "${pkg}${_patsuf}.patch" ] && dos2unix < "${pkg}${_patsuf}.patch" | patch -N -p1 -d "${pkg}"
  fi
  return 0
}

live_dl() {
  local name ver hash jp url sig redir key keys options

  name="$1"

  if [ -z "${CW_GET:-}" ] || echo "${CW_GET}" | grep -q -F "${name}"; then

    ver="$2"
    hash="${3:-}"

    set +x
    jp="$(dependencies_json | jq \
      ".[] | select(.name == \"${name}\")")"

    url="$(  printf '%s' "${jp}" | jq --raw-output '.url' | sed \
        -e "s/{ver}/${ver}/g" \
        -e "s/{vermm}/$(echo "${ver}" | cut -d . -f -2)/g" \
      )"
    sig="$(  printf '%s' "${jp}" | jq --raw-output '.sig' | sed 's/^null$//')"
    redir="$(printf '%s' "${jp}" | jq --raw-output '.redir')"
    keys="$( printf '%s' "${jp}" | jq --raw-output '.keys' | sed 's/^null$//')"

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
  fi
}

# Download llvm-mingw
if [ -n "${CW_DL_LLVM_MINGW:-}" ] && \
   [ ! -d 'llvm-mingw' ]; then
  name=''; vers=''; hash=''
  if   [ "${_OS}" = 'linux' ]; then
    name='llvm-mingw-linux'; vers="${LLVM_MINGW_LINUX_VER_}"; hash="${LLVM_MINGW_LINUX_HASH}"
  elif [ "${_OS}" = 'mac' ]; then
    name='llvm-mingw-mac';   vers="${LLVM_MINGW_MAC_VER_}";   hash="${LLVM_MINGW_MAC_HASH}"
  elif [ "${_OS}" = 'win' ]; then
    name='llvm-mingw-win';   vers="${LLVM_MINGW_WIN_VER_}";   hash="${LLVM_MINGW_WIN_HASH}"
  fi
  if [ -n "${name}" ]; then
    CW_GET='' live_dl "${name}" "${vers}"
    CW_GET='' live_xt "${name}" "${hash}"
    mv "${name}" 'llvm-mingw'
    echo "${vers}" > 'llvm-mingw/version.txt'
  fi
fi

live_dl zlib "${ZLIB_VER_}"
live_xt zlib "${ZLIB_HASH}"

if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nano*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*micro*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*mini*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
  live_dl brotli "${BROTLI_VER_}"
  live_xt brotli "${BROTLI_HASH}"
fi

if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nano*}" = "${_BRANCH}" ]; then
  live_dl nghttp2 "${NGHTTP2_VER_}"
  live_xt nghttp2 "${NGHTTP2_HASH}"

  if [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
    live_dl nghttp3 "${NGHTTP3_VER_}"
    live_xt nghttp3 "${NGHTTP3_HASH}"

    live_dl ngtcp2 "${NGTCP2_VER_}"
    live_xt ngtcp2 "${NGTCP2_HASH}"
  fi
fi

if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nano*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*micro*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*mini*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*winidn*}" = "${_BRANCH}" ]; then
  live_dl libidn2 "${LIBIDN2_VER_}"
  live_xt libidn2 "${LIBIDN2_HASH}"
fi

if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nano*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*micro*}" = "${_BRANCH}" ]; then
  live_dl libgsasl "${LIBGSASL_VER_}"
  live_xt libgsasl "${LIBGSASL_HASH}"
fi

if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nano*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*micro*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*mini*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*schannel*}" = "${_BRANCH}" ]; then
  if [ "${_BRANCH#*libressl*}" != "${_BRANCH}" ]; then
    live_dl libressl "${LIBRESSL_VER_}"
    live_xt libressl "${LIBRESSL_HASH}"
  elif [ "${_BRANCH#*noh3*}" != "${_BRANCH}" ]; then
    if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
      OPENSSL_VER_='3.0.0-beta2'
      OPENSSL_HASH=e76ab22879201b12f014393ee4becec7f264d8f6955b1036839128002868df71
    fi
    live_dl openssl "${OPENSSL_VER_}"
    live_xt openssl "${OPENSSL_HASH}"
  else
    live_dl openssl-quic "${OPENSSL_QUIC_VER_}"
    live_xt openssl-quic "${OPENSSL_QUIC_HASH}"
  fi
fi

if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*nano*}" = "${_BRANCH}" ] && \
   [ "${_BRANCH#*micro*}" = "${_BRANCH}" ]; then
  if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
    LIBSSH2_VER_='1.10.0-dev'
    LIBSSH2_HASH=
    my_curl --location --proto-redir =https \
      --output pkg.bin \
      'https://github.com/libssh2/libssh2/archive/635caa90787220ac3773c1d5ba11f1236c22eae8.tar.gz'
  else
    live_dl libssh2 "${LIBSSH2_VER_}"
  fi
  live_xt libssh2 "${LIBSSH2_HASH}"
fi

if [ "${_BRANCH#*dev*}" != "${_BRANCH}" ]; then
  CURL_VER_='7.83.1-dev'
  CURL_HASH=
  my_curl --location --proto-redir =https \
    --output pkg.bin \
    'https://github.com/curl/curl/archive/462196e6b4a47f924293a0e26b8e9c23d37ac26f.tar.gz'
else
  live_dl curl "${CURL_VER_}"
fi
live_xt curl "${CURL_HASH}"

if [ -n "${SIGN_CODE_GPG_PASS:+1}" ]; then
  live_dl osslsigncode "${OSSLSIGNCODE_VER_}"
  live_xt osslsigncode "${OSSLSIGNCODE_HASH}"
fi

rm -r -f "${gpgdir}"
