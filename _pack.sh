#!/bin/sh -x

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

cd "$(dirname "$0")" || exit

# Map tar to GNU tar, if it exists (e.g. on macOS)
command -v gtar >/dev/null && alias tar=gtar

_cdo="$(pwd)"

_fn="${_DST}/BUILD-README.txt"
cat << EOF > "${_fn}"
Visit the project page for details about these builds and the list of changes:

   ${_URL}
EOF
unix2dos --quiet --keepdate "${_fn}"
touch -c -r "$1" "${_fn}"

_fn="${_DST}/BUILD-HOMEPAGE.url"
cat << EOF > "${_fn}"
[InternetShortcut]
URL=${_URL}
EOF
unix2dos --quiet --keepdate "${_fn}"
touch -c -r "$1" "${_fn}"

find "${_DST}" -depth -type d -exec touch -c -r "$1" '{}' \;

# NOTE: This isn't effective on MSYS2
find "${_DST}" \( -name '*.exe' -o -name '*.dll' -o -name '*.a' \) -exec chmod a-x {} +

create_pack() {
  arch_ext="$2"
  _FLS="$(dirname "$0")/_files"

  (
    cd "${_DST}/.." || exit
    case "${_OS}" in
      win) find "${_BAS}" -exec attrib +A -R {} \;
    esac

    find "${_BAS}" -type f | sort > "${_FLS}"

    rm -f "${_cdo}/${_BAS}${arch_ext}"
    case "${arch_ext}" in
      .tar.xz) tar --create --files-from "${_FLS}" \
        --owner 0 --group 0 --numeric-owner --mode go=rX,u+rw,a-s \
        | xz > "${_cdo}/${_BAS}${arch_ext}";;
      .zip)    zip --quiet -X -9 -@ - < "${_FLS}" > "${_cdo}/${_BAS}${arch_ext}";;
      # Requires: p7zip (MSYS2, Homebrew, Linux rpm), p7zip-full (Linux deb)
      .7z)     7z a -bd -r -mx "${_cdo}/${_BAS}${arch_ext}" "@${_FLS}" >/dev/null;;
    esac
    touch -c -r "$1" "${_cdo}/${_BAS}${arch_ext}"
  )

  ./_signpack.sh "${_cdo}/${_BAS}${arch_ext}"
}

do_post_pack() {
  arch_ext="$1"

  if [ "${_BRANCH#*master*}" != "${_BRANCH}" ]; then
    _suf=
    if [ ! "${PUBLISH_PROD_FROM}" = "${_OS}" ]; then
      _suf="-built-on-${_OS}"
      mv "${_BAS}${arch_ext}" "${_BAS}${_suf}${arch_ext}"
    fi
  else
    # Do not sign test packages
    _suf="-test-built-on-${_OS}"
    mv "${_BAS}${arch_ext}" "${_BAS}${_suf}${arch_ext}"
  fi

  # <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
  case "${_OS}" in
    bsd|mac) TZ=UTC stat -f '%N: %z bytes %Sm' -t '%Y-%m-%d %H:%M' "${_BAS}${_suf}${arch_ext}";;
    *)       TZ=UTC stat --format '%n: %s bytes %y' "${_BAS}${_suf}${arch_ext}";;
  esac

  openssl dgst -sha256 "${_BAS}${_suf}${arch_ext}" | tee -a hashes.txt
  openssl dgst -sha512 "${_BAS}${_suf}${arch_ext}" | tee -a hashes.txt

  if [ "${_BRANCH#*master*}" != "${_BRANCH}" ]; then
  (
    set +x

    hshl="$(openssl dgst -sha256 "${_BAS}${_suf}${arch_ext}" \
      | sed -n -E 's,.+= ([0-9a-fA-F]{64}),\1,p')"
    # https://developers.virustotal.com/v3.0/reference
    out="$(curl --user-agent curl \
      --fail --silent --show-error \
      --request POST 'https://www.virustotal.com/api/v3/files' \
      --header "x-apikey: ${VIRUSTOTAL_APIKEY}" \
      --form "file=@${_BAS}${_suf}${arch_ext}")"
    # shellcheck disable=SC2181
    if [ "$?" = 0 ]; then
      id="$(echo "${out}" | jq --raw-output '.data.id')"
      out="$(curl --user-agent curl \
        --fail --silent --show-error \
        --request GET "https://www.virustotal.com/api/v3/analyses/${id}" \
        --header "x-apikey: ${VIRUSTOTAL_APIKEY}")"
      # shellcheck disable=SC2181
      if [ "$?" = 0 ]; then
        hshr="$(echo "${out}" | jq --raw-output '.meta.file_info.sha256')"
        if [ "${hshr}" = "${hshl}" ]; then
          echo "VirusTotal URL for '${_BAS}${_suf}${arch_ext}':"
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

create_pack "$1" '.tar.xz'
create_pack "$1" '.zip'

ver="${_NAM} ${_VER}"
if ! grep -q -a -F "${ver}" -- "${_BLD}"; then
  echo "${ver}" >> "${_BLD}"
fi

rm -r -f "${_DST:?}"

do_post_pack '.tar.xz'
do_post_pack '.zip'
