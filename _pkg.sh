#!/bin/sh -x

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

cd "$(dirname "$0")" || exit

# Map tar to GNU tar, if it exists (e.g. on macOS)
command -v gtar >/dev/null 2>&1 && alias tar=gtar

_cdo="$(pwd)"

_fn="${_DST}/BUILD-README.txt"
cat << EOF > "${_fn}"
Visit the project page for details about these builds and the list of changes:

   ${_URL}
EOF
touch -c -r "$1" "${_fn}"

_fn="${_DST}/BUILD-HOMEPAGE.url"
cat << EOF > "${_fn}"
[InternetShortcut]
URL=${_URL}
EOF
unix2dos --quiet --keepdate "${_fn}"
touch -c -r "$1" "${_fn}"

find "${_DST}" \( -name '*.txt' -o -name '*.md' -o -name '*.rst' \) -exec unix2dos --quiet --keepdate '{}' +
find "${_DST}" -depth -type d -exec touch -c -r "$1" '{}' \;
# NOTE: This isn't effective on MSYS2:
find "${_DST}" -name '*.a' -exec chmod a-x '{}' +
find "${_DST}" \( -name '*.exe' -o -name '*.dll' \) -exec chmod a+x '{}' +

create_pkg() {
  arch_ext="$2"

  # Alter filename for non-release packages
  if [ "${_BRANCH#*main*}" != "${_BRANCH}" ]; then
    if [ "${PUBLISH_PROD_FROM}" = "${_OS}" ]; then
      _suf=''
    else
      _suf="-built-on-${_OS}"
    fi
  else
    _suf="-test-built-on-${_OS}"
  fi

  _pkg="${_OUT}${_suf}${arch_ext}"

  _FLS="$(dirname "$0")/_files"

  (
    cd "${_DST}/.." || exit
    case "${_OS}" in
      win) find "${_BAS}" -exec attrib +A -R '{}' \;
    esac

    find "${_BAS}" -type f | sort > "${_FLS}"

    rm -f "${_cdo}/${_pkg}"
    case "${arch_ext}" in
      .tar.xz) tar --create \
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
  if [ "${_BRANCH#*main*}" != "${_BRANCH}" ]; then
  (
    set +x

    hshl="$(openssl dgst -sha256 "${_pkg}" \
      | sed -n -E 's,.+= ([0-9a-fA-F]{64}),\1,p')"
    # https://developers.virustotal.com/v3.0/reference
    out="$(echo "x-apikey: ${VIRUSTOTAL_APIKEY}" | curl \
      --user-agent curl --fail --silent --show-error \
      --request POST 'https://www.virustotal.com/api/v3/files' \
      --header @/dev/stdin \
      --form "file=@${_pkg}")"
    # shellcheck disable=SC2181
    if [ "$?" = 0 ]; then
      id="$(echo "${out}" | jq --raw-output '.data.id')"
      out="$(echo "x-apikey: ${VIRUSTOTAL_APIKEY}" | curl \
        --user-agent curl --fail --silent --show-error \
        "https://www.virustotal.com/api/v3/analyses/${id}" \
        --header @/dev/stdin)"
      # shellcheck disable=SC2181
      if [ "$?" = 0 ]; then
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
  )
  fi
}

create_pkg "$1" '.tar.xz'
create_pkg "$1" '.zip'

ver="${_NAM} ${_VER}"
if ! grep -q -a -F "${ver}" -- "${_BLD}"; then
  echo "${ver}" >> "${_BLD}"
fi

rm -r -f "${_DST:?}"
