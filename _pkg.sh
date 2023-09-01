#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

mode="${2:-}"

if [ "${_HOSTOS}" = 'mac' ]; then
  tar() { gtar "$@"; }
fi

_cdo="$(pwd)"

if [ "${_NAM}" != "${_UNIPKG}" ]; then

  find "${_DST}" -depth -type d -exec touch -c -r "$1" '{}' +
  chmod -R a+rw-s,go-w "${_DST}"
  # NOTE: Not effective on MSYS2:
  find "${_DST}" -name '*.a' -exec chmod a-x '{}' +
  if [ "${_OS}" = 'win' ]; then
    find "${_DST}" \( -name '*.exe' -o -name '*.dll' \) -exec chmod a+x '{}' +
  fi

  # First, merge this package into the unified package
  unipkg="${_UNIPKG}"
  {
    [ -d "${_DST}/bin" ]      && rsync --archive --update "${_DST}/bin"     "${unipkg}"
    [ -d "${_DST}/include" ]  && rsync --archive --update "${_DST}/include" "${unipkg}"
    if [ "${_NAM}" = 'libssh2' ]; then
      mkdir -p "${unipkg}/dep/${_NAM}"
      rsync --archive --update "${_DST}/docs" "${unipkg}/dep/${_NAM}"
    fi
    [ -d "${_DST}/lib" ]      && rsync --archive --update "${_DST}/lib" "${unipkg}"
    if [ "${_NAM}" = 'curl' ]; then
      cp -f -p "${_DST}"/*.* "${unipkg}"
      rsync --archive --update "${_DST}/docs" "${unipkg}"
    else
      _NAM_DEP="${unipkg}/dep/${_NAM}"
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
    if [ "${PUBLISH_PROD_FROM}" != "${_HOSTOS}" ]; then
      _suf="${_suf}-built-on-${_HOSTOS}"
    fi
  else
    _suf="${_suf}-test-built-on-${_HOSTOS}"
  fi

  _pkg="${_OUT}${_suf}${arch_ext}"

  _FLS="$(dirname "$0")/_files"

  (
    cd "${_DST}/.."
    case "${_HOSTOS}" in
      win) find "${_BAS}" -exec attrib +A -R '{}' \;
    esac

    find "${_BAS}" -type f -o -type l | sort > "${_FLS}"

    rm -f "${_cdo}/${_pkg}"
    case "${arch_ext}" in
      .tar.xz) TZ=UTC tar --create \
        --format=ustar \
        --owner=0 --group=0 --numeric-owner \
        --files-from "${_FLS}" | xz > "${_cdo}/${_pkg}";;
      .zip) TZ=UTC zip --quiet -9 --strip-extra \
        --names-stdin - < "${_FLS}" > "${_cdo}/${_pkg}";;
    esac
    touch -c -r "$1" "${_cdo}/${_pkg}"
  )

  rm -f "${_FLS}"

  # <filename>: <size> bytes <YYYY-MM-DD> <HH:MM>
  case "${_HOSTOS}" in
    bsd|mac) TZ=UTC stat -f '%N: %z bytes %Sm' -t '%Y-%m-%d %H:%M' "${_pkg}";;
    *)       TZ=UTC stat -c '%n: %s bytes %y' "${_pkg}";;
  esac

  openssl dgst -sha256 "${_pkg}" | sed 's/^SHA256/SHA2-256/g' | tee -a hashes.txt

  # Sign releases only
  if [ -z "${_suf}" ]; then
    ./_sign-pkg.sh "${_pkg}"
  fi
}

if [ "${_NAM}" != "${_UNIPKG}" ]; then
  ver="${_VER}"
  url=''
  [ "${#ver}" -ge 32 ] && ver="$(printf '%.8s' "${ver}")"
  namver="${_NAM} ${ver}"
  [ -f "${_NAM}/__url__.txt" ] && url=" $(cat "${_NAM}/__url__.txt")"
  echo "${namver}${url}" >> "${_UNIMFT}"
  echo "${namver}${url}" >> "${_URLS}"
  if ! grep -q -a -F "${namver}" -- "${_BLD}"; then
    echo "${namver}" >> "${_BLD}"
  fi
elif [ "${mode}" = 'macuni' ] || [ "${_BRANCH#*macuni*}" = "${_BRANCH}" ]; then
  create_pkg "$1" '.tar.xz'
  if [ "${_OS}" = 'win' ]; then
    create_pkg "$1" '.zip'
  fi
fi

if [ "${mode}" = 'unified' ] && [ "${_BRANCH#*macuni*}" != "${_BRANCH}" ]; then
  touch "${_DST}/__macuni__.txt"
else
  rm -r -f "${_DST:?}"
fi
