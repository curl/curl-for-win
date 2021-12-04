#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

# Map tar to GNU tar on macOS
[ "${_OS}" = 'mac' ] && alias tar='gtar'

_cdo="$(pwd)"

_fn="${_DST}/BUILD-README.txt"
cat <<EOF > "${_fn}"
Visit the project page for details about these builds and the list of changes:

   ${_URL}
EOF
touch -c -r "$1" "${_fn}"

_fn="${_DST}/BUILD-HOMEPAGE.url"
cat <<EOF > "${_fn}"
[InternetShortcut]
URL=${_URL}
EOF
unix2dos --quiet --keepdate "${_fn}"
touch -c -r "$1" "${_fn}"

find "${_DST}" -depth -type d -exec touch -c -r "$1" '{}' \;
# NOTE: This is not effective on MSYS2:
find "${_DST}" -name '*.a' -exec chmod a-x '{}' +
find "${_DST}" \( -name '*.exe' -o -name '*.dll' \) -exec chmod a+x '{}' +

create_pkg() {
  arch_ext="$2"

  _suf=''
  # Alter filename for non-default builds
  if [ "${_BRANCH#*mini*}" != "${_BRANCH}" ]; then
    _suf="${_suf}-mini"
  fi
  # Alter filename for non-release packages
  if [ "${_BRANCH#*main*}" != "${_BRANCH}" ]; then
    if [ "${PUBLISH_PROD_FROM}" != "${_OS}" ]; then
      _suf="${_suf}-built-on-${_OS}"
    fi
  else
    _suf="${_suf}-test-built-on-${_OS}"
  fi

  _pkg="${_OUT}${_suf}${arch_ext}"

  _FLS="$(dirname "$0")/_files"

  (
    cd "${_DST}/.."
    case "${_OS}" in
      win) find "${_BAS}" -exec attrib +A -R '{}' \;
    esac

    find "${_BAS}" -type f | sort > "${_FLS}"

    rm -f "${_cdo}/${_pkg}"
    case "${arch_ext}" in
      .tar.xz) tar --create \
        --format=ustar \
        --owner 0 --group 0 --numeric-owner --mode go=rX,u+rw,a-s \
        --files-from "${_FLS}" | xz > "${_cdo}/${_pkg}";;
      .zip) zip --quiet -9 --strip-extra \
        --names-stdin - < "${_FLS}" > "${_cdo}/${_pkg}";;
      # Requires: p7zip (MSYS2, Homebrew, Linux rpm), p7zip-full (Linux deb)
      .7z) 7z a -bd -r -mx "${_cdo}/${_pkg}" "@${_FLS}" >/dev/null;;
    esac
    touch -c -r "$1" "${_cdo}/${_pkg}"
  )

  # <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
  case "${_OS}" in
    bsd|mac) TZ=UTC stat -f '%N: %z bytes %Sm' -t '%Y-%m-%d %H:%M' "${_pkg}";;
    *)       TZ=UTC stat --format '%n: %s bytes %y' "${_pkg}";;
  esac

  openssl dgst -sha256 "${_pkg}" | tee -a hashes.txt
  openssl dgst -sha512 "${_pkg}" | tee -a hashes.txt

  # Sign releases only
  if [ -z "${_suf}" ]; then
    ./_sign-pkg.sh "${_pkg}"
  fi

  # Upload builds to VirusTotal
  if [ "${_BRANCH#*main*}" != "${_BRANCH}" ] && \
     [ -n "${VIRUSTOTAL_APIKEY:+1}" ]; then

    hshl="$(openssl dgst -sha256 "${_pkg}" \
      | sed -n -E 's,.+= ([0-9a-fA-F]{64}),\1,p')"
    # https://developers.virustotal.com/v3.0/reference
    out="$(curl --disable --user-agent '' --fail --silent --show-error \
      --connect-timeout 15 --max-time 60 --retry 3 \
      --request POST 'https://www.virustotal.com/api/v3/files' \
      --header @/dev/stdin \
      --form "file=@${_pkg}" <<EOF || true
x-apikey: ${VIRUSTOTAL_APIKEY}
EOF
)"
    if [ -n "${out}" ]; then
      id="$(echo "${out}" | jq --raw-output '.data.id')"
      out="$(curl --disable --user-agent '' --fail --silent --show-error \
        --connect-timeout 15 --max-time 20 --retry 3 \
        "https://www.virustotal.com/api/v3/analyses/${id}" \
        --header @/dev/stdin <<EOF || true
x-apikey: ${VIRUSTOTAL_APIKEY}
EOF
)"
      if [ -n "${out}" ]; then
        hshr="$(echo "${out}" | jq --raw-output '.meta.file_info.sha256')"
        if [ "${hshr}" = "${hshl}" ]; then
          echo "VirusTotal URL for '${_pkg}':"
          echo "https://www.virustotal.com/file/${hshr}/analysis/"
        else
          echo "VirusTotal hash mismatch with local hash:"
          echo "Remote: '${hshr}' vs."
          echo " Local: '${hshl}'"
        fi
      else
        echo "Error querying VirusTotal upload: $?"
      fi
    else
      echo "Error uploading to VirusTotal: $?"
    fi
  fi
}

create_pkg "$1" '.tar.xz'
create_pkg "$1" '.zip'

ver="${_NAM} ${_VER}"
if ! grep -q -a -F "${ver}" -- "${_BLD}"; then
  echo "${ver}" >> "${_BLD}"
fi

rm -r -f "${_DST:?}"
