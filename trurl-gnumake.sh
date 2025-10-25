#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed -e 's/-gnumake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}"

  # Build

  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} ${_CFLAGS_GLOBAL_RAW}"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LDLIBS=''
  options='TRURL_IGNORE_CURL_CONFIG=1'

  if [[ "${_CONFIG}" != *'debug'* ]]; then
    options+=' NDEBUG=1'
  fi

  if [ "${CW_MAP}" = '1' ]; then
    _map_name='trurl.map'
    if [ "${_OS}" = 'mac' ]; then
      LDFLAGS+=" -Wl,-map,${_map_name}"
    else
      LDFLAGS+=" -Wl,-Map,${_map_name}"
    fi
  fi

  CPPFLAGS+=" -I../curl/${_PP}/include"
  LDLIBS+=" ../curl/${_PP}/lib/libcurl.a"
  if [ "${_OS}" = 'win' ]; then
    CPPFLAGS+=' -DCURL_STATICLIB'
    LDLIBS+=' -lws2_32 -liphlpapi -lcrypt32 -lbcrypt'
  elif [ "${_OS}" = 'mac' ]; then
    if [[ "${_CONFIG}" != *'osnotls'* ]]; then
      LDLIBS+=' -framework Security'
    fi
    LDLIBS+=' -framework SystemConfiguration -framework CoreFoundation'
  fi

  "${_MAKE}" clean
  # shellcheck disable=SC2086
  "${_MAKE}" ${options}

  # Install manually

  mkdir -p "${_PP}/bin"

  cp -f -p "./trurl${BIN_EXT}" "${_PP}/bin/"
  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_map_name}" "${_PP}"/bin/
  fi

  # Make steps for determinism

  readonly _ref='RELEASE-NOTES'

  bin="${_PP}/bin/trurl${BIN_EXT}"

  # shellcheck disable=SC2086
  "${_STRIP_BIN}" ${_STRIPFLAGS_BIN} "${bin}"

  ../_clean-bin.sh "${_ref}" "${bin}"

  ../_sign-code.sh "${_ref}" "${bin}"

  touch -c -r "${_ref}" "${bin}"
  if [ "${CW_MAP}" = '1' ]; then
    touch -c -r "${_ref}" "${_PP}/bin/${_map_name}"
  fi

  ../_info-bin.sh --filetype 'exe' "${bin}"

  # Execute trurl and compiled-in dependency code. This is not secure.
  out="../trurl-version-${_CPUPUB}.txt"
  ${_RUN_BIN} "${bin}" --version | sed 's/\r//g' | tee "${out}"
  [ -s "${out}" ] || rm -f "${out}"

  if [ "${CW_TURL_TEST:-}" = '1' ] && \
     [ "${_RUN_BIN}" != 'true' ]; then
    python3 ./test.py --runner="${_RUN_BIN}" --trurl="${bin}"
  fi

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}"/bin

  cp -f -p "${bin}"       "${_DST}"/bin/
  cp -f -p COPYING        "${_DST}"/COPYING.txt
  cp -f -p README.md      "${_DST}"/README.md
  cp -f -p RELEASE-NOTES  "${_DST}"/RELEASE-NOTES.txt

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_PP}/bin/${_map_name}" "${_DST}"/bin/
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
