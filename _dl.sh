#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

gpgdir='.cw-gpg'; rm -r -f "${gpgdir}"; mkdir -m 700 "${gpgdir}"; gpgdir="$(pwd)/${gpgdir}"
trap 'rm -r -f "${gpgdir:?}"' EXIT HUP INT TERM

dependencies_json() {
cat <<EOF
[
  {
    "name": "brotli",
    "url": "https://github.com/google/brotli/archive/v{ver}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "cares",
    "url": "https://github.com/c-ares/c-ares/releases/download/v{ver}/c-ares-{ver}.tar.gz",
    "sig": ".asc",
    "redir": "redir",
    "keys": "DA7D64E4C82C6294CB73A20E22E3D13B5411B7CA 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2"
  },
  {
    "name": "curl",
    "url": "https://curl.se/download/curl-{ver}.tar.xz",
    "mirror": "https://github.com/curl/curl/releases/download/curl-{veru}/curl-{ver}.tar.xz",
    "sig": ".asc",
    "keys": "27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2"
  },
  {
    "name": "trurl",
    "url": "https://curl.se/trurl/dl/trurl-{ver}.tar.gz",
    "mirror": "https://github.com/curl/trurl/releases/download/trurl-{ver}/trurl-{ver}.tar.gz",
    "ref_url": "https://curl.se/trurl/",
    "sig": ".asc",
    "keys": "27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2"
  },
  {
    "name": "certdata",
    "url": "https://raw.githubusercontent.com/mozilla-firefox/firefox/{commit}/security/nss/lib/ckfw/builtins/certdata.txt",
    "refs": "refs/heads/release",
    "bumpdays": 5
  },
  {
    "name": "psl",
    "url": "https://raw.githubusercontent.com/publicsuffix/list/{commit}/public_suffix_list.dat",
    "bumpdays": 90,
    "gittar": "1"
  },
  {
    "name": "libpsl",
    "url": "https://github.com/rockdaboot/libpsl/releases/download/{ver}/libpsl-{ver}.tar.gz",
    "sig": ".sig",
    "redir": "redir",
    "keys": "1CB27DBC98614B2D5841646D08302DB6A2670428"
  },
  {
    "name": "libssh",
    "url": "https://www.libssh.org/files/{vermm}/libssh-{ver}.tar.xz",
    "ref_url": "https://www.libssh.org/files/",
    "sig": ".asc",
    "keys_comment": "https://www.libssh.org/files/0x03D5DF8CFDD3E8E7_libssh_libssh_org_gpgkey.asc",
    "keys": "88A228D89B07C2C77D0C780903D5DF8CFDD3E8E7"
  },
  {
    "name": "libssh2",
    "url": "https://libssh2.org/download/libssh2-{ver}.tar.xz",
    "mirror": "https://github.com/libssh2/libssh2/releases/download/libssh2-{ver}/libssh2-{ver}.tar.xz",
    "sig": ".asc",
    "keys": "27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2"
  },
  {
    "name": "nghttp2",
    "url": "https://github.com/nghttp2/nghttp2/releases/download/v{ver}/nghttp2-{ver}.tar.xz",
    "sig": ".asc",
    "redir": "redir",
    "keys": "516B622918D15C478AB1EA3A5339A2BE82E07DEC"
  },
  {
    "name": "nghttp3",
    "url": "https://github.com/ngtcp2/nghttp3/releases/download/v{ver}/nghttp3-{ver}.tar.xz",
    "sig": ".asc",
    "redir": "redir",
    "keys": "516B622918D15C478AB1EA3A5339A2BE82E07DEC"
  },
  {
    "name": "ngtcp2",
    "url": "https://github.com/ngtcp2/ngtcp2/releases/download/v{ver}/ngtcp2-{ver}.tar.xz",
    "sig": ".asc",
    "redir": "redir",
    "keys": "516B622918D15C478AB1EA3A5339A2BE82E07DEC"
  },
  {
    "name": "openssl",
    "url": "https://github.com/openssl/openssl/releases/download/openssl-{ver}/openssl-{ver}.tar.gz",
    "sig": ".asc",
    "sha": ".sha256",
    "redir": "redir",
    "tag": "openssl-\\\\d+\\\\.\\\\d+\\\\.\\\\d+$",
    "keys_comment": "Via: https://raw.githubusercontent.com/openssl/openssl/master/doc/fingerprints.txt",
    "keys": "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF 7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C 8657ABB260F056B1E5190839D9C4D26D0E604491 B7C1C14360F353A36862E4D5231C84CDDCC69C45 A21FAB74B0088AA361152586B8EF1A6BA9DA2D5C"
  },
  {
    "name": "libressl",
    "url": "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-{ver}.tar.gz",
    "mirror": "https://github.com/libressl/portable/releases/download/v{ver}/libressl-{ver}.tar.gz",
    "sig": ".asc",
    "keys": "A1EB079B8D3EB92B4EBD3139663AF51BD5E4D8D5"
  },
  {
    "name": "awslc",
    "url": "https://github.com/aws/aws-lc/archive/refs/tags/v{ver}.tar.gz",
    "redir": "redir",
    "tag": "v\\\\d+\\\\.\\\\d+\\\\.\\\\d+$",
    "pinned": true
  },
  {
    "name": "boringssl",
    "url": "https://github.com/google/boringssl/releases/download/{ver}/boringssl-{ver}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "osslsigncode",
    "url": "https://github.com/mtrojnar/osslsigncode/archive/refs/tags/{vermm}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "zlibng",
    "url": "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/{ver}.tar.gz",
    "redir": "redir"
  },
  {
    "name": "zlib",
    "url": "https://zlib.net/zlib-{ver}.tar.xz",
    "mirror": "https://github.com/madler/zlib/releases/download/v{ver}/zlib-{ver}.tar.xz",
    "sig": ".asc",
    "keys": "5ED46A6721D365587791E2AA783FCD8E58BCAFBA"
  },
  {
    "name": "zstd",
    "url": "https://github.com/facebook/zstd/releases/download/v{ver}/zstd-{ver}.tar.gz",
    "sig": ".sig",
    "sha": ".sha256",
    "redir": "redir",
    "keys": "4EF4AC63455FC9F4545D9B7DEF8FE99528B52FFD"
  },
  {
    "name": "llvm-mingw-linux-x86-64",
    "url": "https://github.com/mstorsjo/llvm-mingw/releases/download/{ver}/llvm-mingw-{ver}-ucrt-ubuntu-22.04-x86_64.tar.xz",
    "redir": "redir"
  },
  {
    "name": "llvm-mingw-linux-aarch64",
    "url": "https://github.com/mstorsjo/llvm-mingw/releases/download/{ver}/llvm-mingw-{ver}-ucrt-ubuntu-22.04-aarch64.tar.xz",
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
  local opts
  opts=(--disable --user-agent '' --fail --silent --show-error --globoff \
    --remote-time --xattr \
    --connect-timeout 15 --max-time 80 --retry 3 --max-redirs 10)
  # >&2 echo "my_curl|${opts[*]} $*|"
  if [[ "$*" = *'https://api.github.com/'* && -n "${GITHUB_TOKEN:+1}" ]]; then
    opts+=(--header @/dev/stdin)
    exec <<EOF
Authorization: Bearer ${GITHUB_TOKEN}
EOF
  fi
  curl "${opts[@]}" "$@"
}

my_gpg() {
  local opts
  opts=()
  if [ -z "${APPVEYOR_REPO_BRANCH:-}${CI_COMMIT_REF_NAME:-}${GITHUB_REF_NAME:-}" ]; then
    # Do not populate user GPG configuration with build-related keys, unless
    # this is an automated CI session, where this is fine. In CI environments,
    # as of gnupg 2.2.27, using --homedir or GNUPGHOME causes frequent
    # intermittent fatal errors on later symmetric-key gpg calls that
    # do not use a homedir override.
    opts+=(--homedir "${gpgdir}")
  fi
  # Avoid an empty list to workaround bash 3 erroring "unbound variable"
  opts+=(--batch --keyserver-options timeout=15 --display-charset utf-8 --keyid-format 0xlong)
  gpg "${opts[@]}" "$@"
}

gpg_recv_key() {
  local req
  req="pks/lookup?op=get&options=mr&exact=on&search=0x$1"
  my_curl "https://pgpkeys.eu/${req}"           | my_gpg --import --status-fd 1 || \
  my_curl "https://keyserver.ubuntu.com/${req}" | my_gpg --import --status-fd 1
}

# replace {ver}/{veru}/{vermm} macros with the version number
expandver() {
  # >&2 echo "expandver|$*|"
  sed \
    -e "s/{ver}/$1/g" \
    -e "s/{veru}/$(echo "$1" | tr '.' '_')/g" \
    -e "s/{vermm}/$(echo "$1" | cut -d . -f -2)/g" \
    -e "s/{commit}/${2:-}/g"
}

# convert 'x.y.z' to zero-padded "000x0y0z" numeric format (or leave as-is)
to8digit() {
  local ver
  ver="$(cat)"
  if [[ "${ver}" =~ ([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
    printf '%04d%02d%02d' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[4]:-0}"
  else
    printf '%s' "${ver}"
  fi
}

check_update() {
  local pkg url ourvern newver newvern newcommit slug mask urldir res curlopt commit

  pkg="$1"
  ourvern="${2:-000000}"
  url="$3"
  newver=''
  bumpdays="${9:-90}"
  curlopt="${10}"

  options=()
  [ -n "${curlopt}" ] && options+=("${curlopt}")
  if [[ "${url}" =~ ^https://raw.githubusercontent.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)/(/.+)$ ]]; then
    # content at a specific commit, versioned by the commit date
    slug="${BASH_REMATCH[1]}"
    path="${BASH_REMATCH[2]}"
    # https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28
    # https://api.github.com/repos/<user>/<repo>/commits?path=<filename>[&sha=<refs>]
    refs=''
    [ -n "${8:-}" ] && refs="&sha=${8}"  # e.g. refs/heads/release
    jcommit="$(my_curl --user-agent 'curl' "https://api.github.com/repos/${slug}/commits?path=${path}${refs}" \
      --header 'X-GitHub-Api-Version: 2022-11-28')"
    newver="$(echo    "${jcommit}" | jq --raw-output '.[0].commit.committer.date' | cut -c -10)"  # 'YYYY-MM-DDThh:mm:ssZ' -> 'YYYY-MM-DD'
    newcommit="$(echo "${jcommit}" | jq --raw-output '.[0].sha')"
  elif [[ "${url}" =~ ^https://github.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)/ ]]; then
    slug="${BASH_REMATCH[1]}"
    if [ -n "$6" ]; then
      # raw.githubusercontent.com does not need it.
      newver="$(my_curl "$6" \
        | grep -F "$7" \
        | grep -a -o -E "$8")"
    # heavily rate-limited
    elif [ -n "$4" ]; then
      if [[ "${url}" = *'/refs/heads/'* ]]; then
        heads_or_tags='heads'
      else
        heads_or_tags='tags'
      fi
      # >&2 echo "tag|${tag}|"
      ref="$(my_curl --user-agent 'curl' "https://api.github.com/repos/${slug}/git/refs/${heads_or_tags}" \
        --header 'X-GitHub-Api-Version: 2022-11-28' \
        | jq --raw-output '.[].ref' \
        | grep -a -E "$4" | sort -V | tail -n -1)"
      newver="$(printf '%s' "${ref}" | grep -a -E -o '\d+\.\d+\.\d')"
      # Optionally, check for the presence of a path
      if [ -n "$5" ] && \
         ! my_curl --head "https://raw.githubusercontent.com/${slug}/${ref}/$5" >/dev/null 2>&1; then
        newver=''
      fi
    else
      if [[ "${_CONFIG}" = *'dev'* ]]; then
        newver="$(my_curl --user-agent 'curl' "https://api.github.com/repos/${slug}/releases" \
          --header 'X-GitHub-Api-Version: 2022-11-28' \
          | jq --raw-output 'map(select(.prerelease)) | first | .tag_name' | sed 's/^v//')"
        [ "${newver}" = 'null' ] && newver=''
        [[ ! "${newver}" =~ ^[0-9.]+$ ]] && newver=''
      fi
      if [ -z "${newver}" ]; then
        newver="$(my_curl --user-agent 'curl' "https://api.github.com/repos/${slug}/releases/latest" \
          --header 'X-GitHub-Api-Version: 2022-11-28' \
          | jq --raw-output '.tag_name' | sed 's/^v//')"
      fi
      if [ -n "$8" ]; then
        newver="$(printf '%s' "${newver}" | grep -a -o -E "$8")"
      elif [[ "${newver}" =~ ^[0-9]+\.[0-9]+$ ]]; then
        newver="${newver}.0"
      fi
    fi
  else
    # Special logic for libssh, where each major/minor release resides in
    # a separate subdirectory.
    if [ "${pkg}" = 'libssh' ]; then
      # ugly hack: repurpose 'ref_url' for this case:
      res="$(my_curl "${options[@]}" "$6" | hxclean | hxselect -i -c -s '\n' 'a::attr(href)' \
        | grep -a -o -E -- '[0-9.]+/' | tr -d '/' | sort -V | tail -n -1)"
      url="$6${res}"
      urldir="${url}/"
    elif [ -n "$6" ]; then
      url="$6"
      urldir="${url}"
    else
      urldir="$(dirname "${url}")/"
    fi
    mask="${pkg}[._-]v?([0-9]+(\.[0-9]+)+)\.t"
    [ -n "$8" ] && mask="$8"
    # >&2 echo "mask|${mask}|"
    res="$(my_curl "${options[@]}" "${urldir}" | hxclean | hxselect -i -c -s '\n' 'a::attr(href)' \
      | grep -a -o -E -- "${mask}" | sort -V | tail -n -1)"
    # >&2 echo "res|${res}|"
    if [[ "${res}" =~ ${mask} ]]; then
      newver="${BASH_REMATCH[1]}"
    fi
  fi
  if [ -n "${newver}" ]; then
    if [[ "${url}" =~ ^https://raw.githubusercontent.com/ ]]; then
      case "$(uname)" in
        Darwin*|*BSD)
          unixold="$(date -u -j -f '%Y-%m-%d' "${ourvern}" '+%s')"
          unixnew="$(date -u -j -f '%Y-%m-%d' "${newver}" '+%s')"
          ;;
        *)  # GNU date
          unixold="$(date -d "${ourvern}" '+%s')"
          unixnew="$(date -d "${newver}" '+%s')"
          ;;
      esac
      diff_days=$(( (unixnew - unixold) / 86400 ))
      if [ "${diff_days}" -ge "${bumpdays}" ]; then
        printf '%s' "${newver}-${newcommit}"
      fi
    elif [ "${#newver}" -ge 32 ]; then  # hash
      if [ "${newver}" != "${ourvern}" ]; then
        printf '%s' "${newver}"
      fi
    else
      newvern="$(printf '%s' "${newver}" | to8digit)"
      if [[ "${newvern}" > "${ourvern}" ]]; then
        printf '%s' "${newver}"
      fi
    fi
  fi
}

check_dl() {
  local name url keys sig sha redir options key ok hash_calc hash_got curlopt gittar slug commit dcommit

  name="$1"
  url="$2"
  sig="$3"
  sha="$4"
  redir="$5"
  keys="$6"
  curlopt="$7"
  gittar="$8"

  if [[ "${url}" =~ ^https://raw.githubusercontent.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)/([a-fA-F0-9]+)/(.+)$ ]]; then
    slug="${BASH_REMATCH[1]}"
    commit="${BASH_REMATCH[2]}"
    if [ "${gittar}" = '1' ]; then
      # Download the whole tarball for the commit hash. GitHub sets the timestamp of all files to the commit timestamp.
      # (so does Forgejo, Gitea, GitLab, and probably more. Notably not true for googlesource.com tarballs.)
      url="https://github.com/${slug}/archive/${commit}.tar.gz"
      redir='redir'
    fi
  fi

  options=()
  [ -n "${curlopt}" ] && options+=("${curlopt}")
  [ "${redir}" = 'redir' ] && options+=(--location --proto-redir '=https')
  options+=(--output pkg.bin "${url}")
  if [ -n "${sig}" ]; then
    [[ "${sig}" = 'https://'* ]] || sig="${url}${sig}"
    options+=(--output pkg.sig "${sig}")
  fi
  [ -n "${sha}" ] && options+=(--output pkg.sha "${url}${sha}")
  my_curl "${options[@]}"

  ok='0'
  hash_calc="$(sha256sum --tag pkg.bin | grep -a -i -o -E '[0-9a-f]{64}$')"
  if [ -n "${sig}" ]; then
    if [ ! -s pkg.sig ]; then
      >&2 echo "! ${name}: Verify: Failed (Signature expected, but missing)"
    else
      for key in ${keys}; do
        gpg_recv_key "${key}" >/dev/null 2>&1
      done

      if my_gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin >/dev/null 2>&1; then
        >&2 echo "! ${name}: Verify: OK (Valid PGP signature)"
        ok='1'
      else
        >&2 echo "! ${name}: Verify: Failed (PGP signature)"
      fi
    fi

    if [ "${ok}" = '1' ] && [ -n "${sha}" ]; then
      hash_got="$(grep -a -i -o -E '[0-9A-Fa-f]{64,}' pkg.sha | tr '[:upper:]' '[:lower:]')"
      if [ "${hash_calc}" = "${hash_got}" ]; then
        >&2 echo "! ${name}: Verify: OK (Matching hash)"
      else
        >&2 echo "! ${name}: Verify: Failed (Mismatching hash)"
        ok='0'
      fi
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
  local keypkg newcurl newdep pkg name ourver_raw ourver ourvern hashenv hash jp url pin
  local newver_raw newver newcommit newhash sig sha redir keys urlver curlopt gittar

  set +x

  keypkg='curl'

  newcurl=0
  newdep=0

  while read -r pkg; do
    if [[ "${pkg}" =~ ^([A-Z0-9_]+)_VER_=(.+)$ ]]; then
      nameenv="${BASH_REMATCH[1]}"
      name="${nameenv,,}"
      name="${name//_/-}"
      ourver_raw="${BASH_REMATCH[2]}"
      if [[ "${ourver_raw}" =~ (.+)-([a-f0-9]{40,}) ]]; then
        ourver="${BASH_REMATCH[1]}"
      else
        ourver="${ourver_raw}"
      fi
      ourvern="$(printf '%s' "${ourver}" | to8digit)"

      hashenv="${nameenv}_HASH"
      eval hash="\${${hashenv}:-}"

      jp="$(dependencies_json | jq \
        ".[] | select(.name == \"${name}\")")"

      newhash=''

      if [ -n "${jp}" ]; then
        url="$(     printf '%s' "${jp}" | jq --raw-output '.url')"
        pin="$(     printf '%s' "${jp}" | jq --raw-output '.pinned')"
        tag="$(     printf '%s' "${jp}" | jq --raw-output '.tag' | sed 's/^null$//')"
        hasfile="$( printf '%s' "${jp}" | jq --raw-output '.hasfile' | sed 's/^null$//')"
        ref_url="$( printf '%s' "${jp}" | jq --raw-output '.ref_url' | sed 's/^null$//')"
        ref_expr="$(printf '%s' "${jp}" | jq --raw-output '.ref_expr' | sed 's/^null$//')"
        refs="$(    printf '%s' "${jp}" | jq --raw-output '.refs' | sed 's/^null$//')"
        bumpdays="$(printf '%s' "${jp}" | jq --raw-output '.bumpdays' | sed 's/^null$//')"
        curlopt="$( printf '%s' "${jp}" | jq --raw-output '.curlopt' | sed 's/^null$//')"

        if [ "${pin}" = 'true' ]; then
          >&2 echo "! ${name}: Version pinned. Skipping."
        else
          # Some projects use part of the version number to form the path.
          # Caveat: Major/minor upgrades are not detected in that case.
          # (e.g. libssh)
          urlver="$(printf '%s' "${url}" | expandver "${ourver}")"
          newver_raw="$(check_update "${name}" \
            "${ourvern}" \
            "${urlver}" \
            "${tag}" \
            "${hasfile}" \
            "${ref_url}" \
            "${ref_expr}" \
            "${refs}" \
            "${bumpdays}" \
            "${curlopt}")"

          if [[ "${newver_raw}" =~ (.+)-([a-f0-9]{40,}) ]]; then
            newver="${BASH_REMATCH[1]}"
            newcommit="${BASH_REMATCH[2]}"
          else
            newver="${newver_raw}"
            newcommit=''
          fi
          if [ -n "${newver}" ]; then
            >&2 echo "! ${name}: New version found: |${newver}|"

            if [ -n "${hash}" ]; then
              sig="$(   printf '%s' "${jp}" | jq --raw-output '.sig' | sed 's/^null$//')"
              sha="$(   printf '%s' "${jp}" | jq --raw-output '.sha' | sed 's/^null$//')"
              redir="$( printf '%s' "${jp}" | jq --raw-output '.redir')"
              keys="$(  printf '%s' "${jp}" | jq --raw-output '.keys' | sed 's/^null$//')"
              gittar="$(printf '%s' "${jp}" | jq --raw-output '.gittar' | sed 's/^null$//')"

              urlver="$(printf '%s' "${url}" | expandver "${newver}" "${newcommit}")"
              sigver="$(printf '%s' "${sig}" | expandver "${newver}")"
              newhash="$(check_dl \
                "${name}" \
                "${urlver}" \
                "${sigver}" \
                "${sha}" \
                "${redir}" \
                "${keys}" \
                "${curlopt}" \
                "${gittar}")"
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
        newver_raw="${ourver_raw}"
        # shellcheck disable=SC2154
        newhash="${hash}"
      fi

      echo "export ${nameenv^^}_VER_='${newver_raw}'"
      [ -n "${hash}" ] && echo "export ${hashenv}=${newhash}"
    fi
  done <<< "$(env | grep -a -E '^[A-Z0-9_]+_VER_' | \
    sed "s/^${keypkg}/0X0X/g" | sort | \
    sed "s/^0X0X/${keypkg}/g")"

  if [ "${newcurl}" = '1' ]; then
    _REV='1'  # Reset revision on each curl version bump
  elif [ "${newdep}" = '1' ]; then
    ((_REV+=1))  # Bump revision with each dependency version bump
  fi

  echo "export _REV=${_REV}"
}

if [ "${1:-}" = 'bump' ]; then
  bump
  rm -r -f "${gpgdir:?}"
  exit
fi

echo "Build: REV(${_REVSUFFIX})"

# Quit if any of the lines fail
set -e

if [ "${_HOST}" = 'mac' ]; then
  tar() { gtar "$@"; }
fi

my_gpg --version | grep -a -F gpg

# Required for a git command to work later in the script, to avoid:
# "fatal: detected dubious ownership in repository at '<sandbox-path>'
# To add an exception for this directory, call:"
_pwd="$(pwd)"
if ! git config --global safe.directory | grep -q -F "${_pwd}"; then
  git config --global --add safe.directory "${_pwd}"
fi

export _PATCHSUFFIX
if [[ "${_CONFIG}" = *'dev'* ]]; then
  _PATCHSUFFIX='.dev'
elif [[ "${_CONFIG}" != *'main'* ]]; then
  _PATCHSUFFIX='.test'
else
  _PATCHSUFFIX=''
fi

live_xt() {
  local pkg hash
  pkg="$1"
  if [[ -z "${CW_GET:-}"   || " ${CW_GET} "    = *" ${pkg} "* ]] && \
     [[ -z "${CW_NOGET:-}" || " ${CW_NOGET} " != *" ${pkg} "* ]]; then
    hash="$(sha256sum --tag pkg.bin)"
    echo "${hash}"
    if [ -n "${2:-}" ]; then
      echo "${hash}" | grep -q -a -F -w -- "${2:-}" || exit 1
    fi
    rm -r -f "${pkg:?}"; mkdir "${pkg}"
    if [ "${pkg}" = 'certdata' ]; then
      mv pkg.bin "${pkg}/${_CERTDATA}"  # It is a single file in this case
    else
      tar --no-same-owner --no-same-permissions --strip-components="${3:-1}" -xf pkg.bin --directory="${pkg}"
      [ -f "${pkg}${_PATCHSUFFIX}.patch" ] && patch --forward --strip=1 --directory="${pkg}" < "${pkg}${_PATCHSUFFIX}.patch"
    fi
    rm -f pkg.bin pkg.sig
    [ -f "__${pkg}.url" ] && mv "__${pkg}.url" "${pkg}/__url__.txt"
  fi
  return 0
}

live_dl() {
  local name ver hash jp url mirror sig redir key keys options curlopt sha gittar slug commit dcommit

  name="$1"

  if [[ -z "${CW_GET:-}"   || " ${CW_GET} "    = *" ${name} "* ]] && \
     [[ -z "${CW_NOGET:-}" || " ${CW_NOGET} " != *" ${name} "* ]]; then

    ver_raw="$2"
    hash="${3:-}"

    if [[ "${ver_raw}" =~ (.+)-([a-f0-9]{40,}) ]]; then
      ver="${BASH_REMATCH[1]}"
      commit="${BASH_REMATCH[2]}"
    else
      ver="${ver_raw}"
      commit=''
    fi

    set +x
    jp="$(dependencies_json | jq \
      ".[] | select(.name == \"${name}\")")"

    url="$(    printf '%s' "${jp}" | jq --raw-output '.url' | expandver "${ver}" "${commit}")"
    mirror="$( printf '%s' "${jp}" | jq --raw-output '.mirror' | sed 's/^null$//' | expandver "${ver}" "${commit}")"
    sigraw="$( printf '%s' "${jp}" | jq --raw-output '.sig' | sed 's/^null$//' | expandver "${ver}")"
    redir="$(  printf '%s' "${jp}" | jq --raw-output '.redir')"
    keys="$(   printf '%s' "${jp}" | jq --raw-output '.keys' | sed 's/^null$//')"
    curlopt="$(printf '%s' "${jp}" | jq --raw-output '.curlopt' | sed 's/^null$//')"
    gittar="$( printf '%s' "${jp}" | jq --raw-output '.gittar' | sed 's/^null$//')"

    dcommit=''
    if [[ "${url}" =~ ^https://raw.githubusercontent.com/([a-zA-Z0-9-]+/[a-zA-Z0-9-]+)/[^/]+(/.+)$ ]]; then
      slug="${BASH_REMATCH[1]}"
      path="${BASH_REMATCH[2]}"
      if [ "${gittar}" = '1' ]; then
        # Download the whole tarball for the commit hash. GitHub sets the timestamp of all files to the commit timestamp.
        # (so does Forgejo, Gitea, GitLab, and probably more. Notably not true for googlesource.com tarballs.)
        url="https://github.com/${slug}/archive/${commit}.tar.gz"
        redir='redir'
      else
        # Use the GitHub API to find out the timestamp of the downloaded file
        sha=''
        [ -n "${commit:-}" ] && sha="&sha=${commit}"
        # Tweak the received date format to be accepted also by busybox (on Alpine).
        # https://busybox.net/downloads/BusyBox.html#date
        dcommit="$(my_curl --user-agent 'curl' "https://api.github.com/repos/${slug}/commits?path=${path}${sha}" \
          --header 'X-GitHub-Api-Version: 2022-11-28' \
          | jq --raw-output '.[0].commit.committer.date' | sed 's/^null$//' | tr 'T' ' ' | tr -d 'Z')"  # 'YYYY-MM-DDThh:mm:ssZ' -> 'YYYY-MM-DD hh:mm:ss'
        echo "! Detected file timestamp: |${dcommit}|"
      fi
    fi

    options=(--retry-all-errors)
    [ -n "${curlopt}" ] && options+=("${curlopt}")
    [ "${redir}" = 'redir' ] && options+=(--location --proto-redir '=https')
    options+=(--output pkg.bin "${url}")
    sig="${sigraw}"
    if [ -n "${sig}" ]; then
      [[ "${sig}" = 'https://'* ]] || sig="${url}${sig}"
      options+=(--output pkg.sig "${sig}")
    fi
    set -x
    if ! my_curl "${options[@]}"; then
      if [ -n "${mirror}" ]; then
        options=(--retry-all-errors)
        if [[ "${mirror}" = 'https://github.com/'* ]]; then
          options+=(--location --proto-redir '=https')
        fi
        options+=(--output pkg.bin "${mirror}")
        sig="${sigraw}"
        if [ -n "${sig}" ]; then
          [[ "${sig}" = 'https://'* ]] || sig="${mirror}${sig}"
          options+=(--output pkg.sig "${sig}")
        fi
        if ! my_curl "${options[@]}"; then
          >&2 echo "! ${name}: Download: Failed (from mirror)"
          exit 1
        fi
      else
        >&2 echo "! ${name}: Download: Failed"
        exit 1
      fi
    fi
    if [ -n "${dcommit}" ]; then
      TZ=UTC touch -c -d "${dcommit}" pkg.bin
      ls -l pkg.bin  # log to verify
    fi

    if [ -n "${sig}" ]; then
      if [ ! -s pkg.sig ]; then
        >&2 echo "! ${name}: Verify: Failed (Signature expected, but missing)"
        exit 1
      else
        for key in ${keys}; do
          gpg_recv_key "${key}"
        done
        my_gpg --verify-options show-primary-uid-only --verify pkg.sig pkg.bin || exit 1
      fi
    fi

    echo "${url}" > "__${name}.url"

    if [ -n "${hash}" ] && [ "${gittar}" != '1' ]; then
      live_xt "${name}" "${hash}"
    else
      true
    fi
  fi
}

# Download llvm-mingw
if [ "${_OS}" = 'win' ] && \
   [ "${CW_LLVM_MINGW_DL:-}" = '1' ] && \
   [ ! -d 'llvm-mingw' ]; then
  name=''; vers=''; hash=''; arch="$(uname -m)"
  if   [ "${_HOST}-${arch}" = 'linux-x86_64' ]; then
    name='llvm-mingw-linux-x86-64';  vers="${LLVM_MINGW_LINUX_X86_64_VER_}";  hash="${LLVM_MINGW_LINUX_X86_64_HASH}"
  elif [ "${_HOST}-${arch}" = 'linux-aarch64' ]; then
    name='llvm-mingw-linux-aarch64'; vers="${LLVM_MINGW_LINUX_AARCH64_VER_}"; hash="${LLVM_MINGW_LINUX_AARCH64_HASH}"
  elif [ "${_HOST}" = 'mac' ]; then
    name='llvm-mingw-mac';           vers="${LLVM_MINGW_MAC_VER_}";           hash="${LLVM_MINGW_MAC_HASH}"
  elif [ "${_HOST}" = 'win' ]; then
    name='llvm-mingw-win';           vers="${LLVM_MINGW_WIN_VER_}";           hash="${LLVM_MINGW_WIN_HASH}"
  fi
  if [ -n "${name}" ]; then
    CW_GET='' live_dl "${name}" "${vers}"
    CW_GET='' live_xt "${name}" "${hash}"
    mv "${name}" 'llvm-mingw'
    echo "${vers}" > 'llvm-mingw/version.txt'
  fi
fi

# Translate config to a list of dependencies

export _DEPS='curl'

if [[ ! "${_CONFIG}" =~ (zero|nozlib) ]]; then
  if [[ "${_CONFIG}" = *'zlibold'* ]]; then
    _DEPS+=' zlibold'
  else
    _DEPS+=' zlibng'
  fi
fi

if [[ ! "${_CONFIG}" =~ (zero|bldtst|pico|nano|micro|mini) ]]; then
  if [[ "${_CONFIG}" != *'nobrotli'* ]]; then
    _DEPS+=' brotli'
  fi
  if [[ "${_CONFIG}" != *'nozstd'* ]]; then
    _DEPS+=' zstd'
  fi
fi

if [[ "${_CONFIG}" = *'cares'* ]]; then
  _DEPS+=' cares'
fi

if [[ ! "${_CONFIG}" =~ (zero|bldtst|nocookie) ]]; then
  _DEPS+=' psl'
  _DEPS+=' libpsl'
fi

need_certdata=0

if [[ ! "${_CONFIG}" =~ (zero|bldtst) || "${_CONFIG}" = *'libssh1'* ]]; then
  if   [[ "${_CONFIG}" = *'libressl'* ]]; then
    _DEPS+=' libressl'
    need_certdata=1
  elif [[ "${_CONFIG}" = *'awslc'* ]]; then
    _DEPS+=' awslc'
    need_certdata=1
  elif [[ "${_CONFIG}" = *'boringssl'* ]]; then
    _DEPS+=' boringssl'
    need_certdata=1
  elif [[ "${_CONFIG}" = *'openssl'* ]]; then
    _DEPS+=' openssl'
    need_certdata=1
  elif [[ "${_OS}" = 'linux' ]] || \
       [[ ! "${_CONFIG}" =~ (pico|nano|micro|mini|ostls) ]]; then
    _DEPS+=' libressl'
    need_certdata=1
  fi
fi

if [[ ! "${_CONFIG}" =~ (zero|bldtst|pico|nano) ]]; then
  _DEPS+=' nghttp2'
  if [[ "${_CONFIG}" != *'noh3'* ]]; then
    _DEPS+=' nghttp3'
    _DEPS+=' ngtcp2'
  fi
fi

if [[ ! "${_CONFIG}" =~ (zero|bldtst|pico|nano|micro) || "${_CONFIG}" =~ (libssh1|libssh2) ]]; then
  if [[ "${_CONFIG}" = *'libssh1'* ]]; then
    _DEPS+=' libssh1'
  else
    _DEPS+=' libssh2'
  fi
fi

if [ "${need_certdata}" = '1' ] && \
   [ "${_OS}" != 'mac' ]; then
  _DEPS+=' certdata'
fi

if [[ "${_CONFIG}" != *'notrurl'* && "${_CONFIG}" =~ (dev|test|trurl) ]]; then
  _DEPS+=' trurl'
fi

# Download dependencies

if [[ "${_DEPS}" = *'zlibng'* ]]; then
  live_dl zlibng "${ZLIBNG_VER_}"
  live_xt zlibng "${ZLIBNG_HASH}"
fi
if [[ "${_DEPS}" = *'zlibold'* ]]; then
  live_dl zlib "${ZLIB_VER_}"
  live_xt zlib "${ZLIB_HASH}"
fi
if [[ "${_DEPS}" = *'brotli'* ]]; then
  live_dl brotli "${BROTLI_VER_}"
  live_xt brotli "${BROTLI_HASH}"
fi
if [[ "${_DEPS}" = *'zstd'* ]]; then
  live_dl zstd "${ZSTD_VER_}"
  live_xt zstd "${ZSTD_HASH}"
fi
if [[ "${_DEPS}" = *'cares'* ]]; then
  live_dl cares "${CARES_VER_}"
  live_xt cares "${CARES_HASH}"
fi
if [[ "${_DEPS}" = *'nghttp2'* ]]; then
  live_dl nghttp2 "${NGHTTP2_VER_}"
  live_xt nghttp2 "${NGHTTP2_HASH}"
fi
if [[ "${_DEPS}" = *'nghttp3'* ]]; then
  live_dl nghttp3 "${NGHTTP3_VER_}"
  live_xt nghttp3 "${NGHTTP3_HASH}"
fi
if [[ "${_DEPS}" = *'ngtcp2'* ]]; then
  live_dl ngtcp2 "${NGTCP2_VER_}"
  live_xt ngtcp2 "${NGTCP2_HASH}"
fi
if [[ "${_DEPS}" = *'psl'* ]]; then
  live_dl psl "${PSL_VER_}"
  live_xt psl "${PSL_HASH}"
fi
if [[ "${_DEPS}" = *'libpsl'* ]]; then
  live_dl libpsl "${LIBPSL_VER_}"
  live_xt libpsl "${LIBPSL_HASH}"
fi
if [[ "${_DEPS}" = *'libressl'* ]]; then
  if [[ "${_CONFIG}" = *'dev'* ]] && false; then
    LIBRESSL_VER_='3.9.0'
    LIBRESSL_HASH=1cc232418498de305e6d5cb80c94a16415c01dcb3cd98f2e8c3a2202091a3420
  fi
  live_dl libressl "${LIBRESSL_VER_}"
  live_xt libressl "${LIBRESSL_HASH}"
fi
if [[ "${_DEPS}" = *'awslc'* ]]; then
  live_dl awslc "${AWSLC_VER_}"
  live_xt awslc "${AWSLC_HASH}"
fi
if [[ "${_DEPS}" = *'boringssl'* ]]; then
  live_dl boringssl "${BORINGSSL_VER_}"
  live_xt boringssl "${BORINGSSL_HASH}"
fi
if [[ "${_DEPS}" = *'openssl'* ]]; then
  if [[ "${_CONFIG}" = *'dev'* ]] && false; then
    OPENSSL_VER_='3.6.0'
    OPENSSL_HASH=
  fi
  live_dl openssl "${OPENSSL_VER_}"
  live_xt openssl "${OPENSSL_HASH}"
fi
if [[ "${_DEPS}" = *'libssh1'* ]]; then
  # shellcheck disable=SC2153
  live_dl libssh "${LIBSSH_VER_}"
  # shellcheck disable=SC2153
  live_xt libssh "${LIBSSH_HASH}"
fi
if [[ "${_DEPS}" = *'libssh2'* ]]; then
  if [[ "${_CONFIG}" = *'dev'* ]]; then
    LIBSSH2_HASH=
    if [[ -z "${CW_GET:-}"   || " ${CW_GET} "    = *' libssh2 '* ]] && \
       [[ -z "${CW_NOGET:-}" || " ${CW_NOGET} " != *' libssh2 '* ]]; then
      LIBSSH2_REV_="${LIBSSH2_REV_:-master}"
      tmp="$(mktemp)"
      my_curl --user-agent 'curl' "https://api.github.com/repos/libssh2/libssh2/commits/${LIBSSH2_REV_}" \
        --retry-all-errors --retry 10 \
        --header 'X-GitHub-Api-Version: 2022-11-28' --output "${tmp}"
      rev="$(jq --raw-output '.sha' "${tmp}")"
      rm -r -f "${tmp}"
      [ -n "${rev}" ] && LIBSSH2_REV_="${rev}"
      url="https://github.com/libssh2/libssh2/archive/${LIBSSH2_REV_}.tar.gz"
      echo "${url}" > '__libssh2.url'
      my_curl --location --proto-redir =https --output pkg.bin "${url}"
      live_xt libssh2 "${LIBSSH2_HASH}"
    fi
  else
    live_dl libssh2 "${LIBSSH2_VER_}"
    live_xt libssh2 "${LIBSSH2_HASH}"
  fi
  if [[ "${_CONFIG}" = *'dev'* ]] || [ -d 'libssh2/.git' ]; then
    LIBSSH2_VER_="$(grep -a -F 'define LIBSSH2_VERSION ' 'libssh2/include/libssh2.h' | grep -o -E '".+"' | tr -d '"')"
  fi
fi
if [[ "${_DEPS}" = *'certdata'* ]]; then
  live_dl certdata "${CERTDATA_VER_}"
  live_xt certdata "${CERTDATA_HASH}"
fi
if [[ "${_DEPS}" = *'curl'* ]]; then
  if [[ "${_CONFIG}" = *'dev'* ]]; then
    CURL_HASH=
    if [[ -z "${CW_GET:-}"   || " ${CW_GET} "    = *' curl '* ]] && \
       [[ -z "${CW_NOGET:-}" || " ${CW_NOGET} " != *' curl '* ]]; then
      CURL_REV_="${CURL_REV_:-master}"
      tmp="$(mktemp)"
      my_curl --user-agent 'curl' "https://api.github.com/repos/curl/curl/commits/${CURL_REV_}" \
        --retry-all-errors --retry 10 \
        --header 'X-GitHub-Api-Version: 2022-11-28' --output "${tmp}"
      rev="$(jq --raw-output '.sha' "${tmp}")"
      rm -r -f "${tmp}"
      [ -n "${rev}" ] && CURL_REV_="${rev}"
      url="https://github.com/curl/curl/archive/${CURL_REV_}.tar.gz"
      echo "${url}" > '__curl.url'
      my_curl --location --proto-redir =https --output pkg.bin "${url}"
      live_xt curl "${CURL_HASH}"
    fi
  else
    live_dl curl "${CURL_VER_}"
    live_xt curl "${CURL_HASH}"
  fi
  if [[ "${_CONFIG}" = *'dev'* ]] || [ -d 'curl/.git' ]; then
    CURL_VER_="$(grep -a -F 'define LIBCURL_VERSION' 'curl/include/curl/curlver.h' | grep -o -E '".+"' | tr -d '"')"
  fi
fi
if [[ "${_DEPS}" = *'trurl'* ]]; then
  if [[ "${_CONFIG}" = *'dev'* ]]; then
    TRURL_HASH=
    if [[ -z "${CW_GET:-}"   || " ${CW_GET} "    = *' trurl '* ]] && \
       [[ -z "${CW_NOGET:-}" || " ${CW_NOGET} " != *' trurl '* ]]; then
      TRURL_REV_="${TRURL_REV_:-master}"
      tmp="$(mktemp)"
      my_curl --user-agent 'curl' "https://api.github.com/repos/curl/trurl/commits/${TRURL_REV_}" \
        --retry-all-errors --retry 10 \
        --header 'X-GitHub-Api-Version: 2022-11-28' --output "${tmp}"
      rev="$(jq --raw-output '.sha' "${tmp}")"
      rm -r -f "${tmp}"
      [ -n "${rev}" ] && TRURL_REV_="${rev}"
      url="https://github.com/curl/trurl/archive/${TRURL_REV_}.tar.gz"
      echo "${url}" > '__trurl.url'
      my_curl --location --proto-redir =https --output pkg.bin "${url}"
      # shellcheck disable=SC2153
      live_xt trurl "${TRURL_HASH}"
    fi
  else
    # shellcheck disable=SC2153
    live_dl trurl "${TRURL_VER_}"
    # shellcheck disable=SC2153
    live_xt trurl "${TRURL_HASH}"
  fi
  if [[ "${_CONFIG}" = *'dev'* && -d 'trurl' ]] || [ -d 'trurl/.git' ]; then
    TRURL_VER_="$(grep -a -F 'define TRURL_VERSION_TXT' 'trurl/version.h' | grep -o -E '".+"' | tr -d '"')-DEV"
  fi
fi

if [ "${_OS}" = 'win' ] && \
   [ -n "${SIGN_CODE_AGE_PASS:+1}" ] && \
  ! command -v osslsigncode >/dev/null 2>&1; then
  live_dl osslsigncode "${OSSLSIGNCODE_VER_}"
  live_xt osslsigncode "${OSSLSIGNCODE_HASH}"
  ./osslsigncode.sh "${OSSLSIGNCODE_VER_}"
fi

rm -r -f "${gpgdir:?}"
