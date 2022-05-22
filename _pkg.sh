#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

if [ "${_OS}" = 'mac' ]; then
  tar() { gtar "$@"; }
fi

_cdo="$(pwd)"

_NAMX="$(printf '%s' "${_NAM}" | tr '_' '-')"

if [ "${_NAM}" != "${_UNIPKG}" ]; then

  find "${_DST}" -depth -type d -exec touch -c -r "$1" '{}' +
  # NOTE: Not effective on MSYS2:
  find "${_DST}" -name '*.a' -exec chmod a-x '{}' +
  find "${_DST}" \( -name '*.exe' -o -name '*.dll' \) -exec chmod a+x '{}' +

  # First, merge this package into the unified package
  unipkg="${_UNIPKG}"
  {
    [ -d "${_DST}/bin" ]      && rsync --archive --update "${_DST}/bin"     "${unipkg}"
    [ -d "${_DST}/include" ]  && rsync --archive --update "${_DST}/include" "${unipkg}"
    [ "${_NAM}" = 'libssh2' ] && rsync --archive --update "${_DST}/docs"    "${unipkg}/dep/${_NAM}"
    if [ -d "${_DST}/lib64" ]; then  # openssl
      rsync --archive --update "${_DST}/lib64/" "${unipkg}/lib/"
    else
      rsync --archive --update "${_DST}/lib"    "${unipkg}"
    fi
    if [ "${_NAM}" = 'curl' ]; then
      cp -f -p "${_DST}"/*.* "${unipkg}"
      rsync --archive --update "${_DST}/docs" "${unipkg}"
    else
      _NAM_DEP="${unipkg}/dep/${_NAMX}"
      mkdir -p "${_NAM_DEP}"
      cp -f -p "${_DST}"/*.* "${_NAM_DEP}"
    fi
  }
fi

create_pkg() {
  arch_ext="$2"

  if [ "${_NAM}" != "${_UNIPKG}" ]; then
    _suf="${_FLAV}"
  else
    _suf=''  # _FLAV already added, do not add it a second time
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

if [ "${_NAM}" != "${_UNIPKG}" ]; then
  ver="${_NAMX} ${_VER}"
  echo "${ver}" >> "${_UNIMFT}"
  if ! grep -q -a -F "${ver}" -- "${_BLD}"; then
    echo "${ver}" >> "${_BLD}"
  fi
else
  create_pkg "$1" '.tar.xz'
  create_pkg "$1" '.zip'
fi

rm -r -f "${_DST:?}"
