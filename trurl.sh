#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

if [ "${TRURL_VER_}" = '0.16.1' ]; then
  ./trurl-gnumake.sh "$@"
  exit $?
fi

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  # Build

  options=''
  CPPFLAGS=''
  LDFLAGS=''
  LIBS=''

  if [ "${CW_MAP}" = '1' ]; then
    _map_name='trurl.map'
    if [ "${_OS}" = 'mac' ]; then
      LDFLAGS+=" -Wl,-map,${_map_name}"
    else
      LDFLAGS+=" -Wl,-Map,${_map_name}"
    fi
  fi

  # Ugly hack. Everything breaks without this due to the accidental ordering
  # of libs and objects, and offering no universal way to (re)insert libs at
  # specific positions. Linker complains about a missing --end-group, then
  # adds it automatically anyway.
  if [ "${_LD}" = 'ld' ]; then
    LDFLAGS+=' -Wl,--start-group'
  fi

  options+=" -DCURL_INCLUDE_DIR=${_TOP}/curl/${_PP}/include"
  options+=" -DCURL_LIBRARY=${_TOP}/curl/${_PP}/lib/libcurl.a"
  if [ "${_OS}" = 'win' ]; then
    CPPFLAGS+=' -DCURL_STATICLIB'
    LIBS+=' -lws2_32 -lbcrypt'
  fi

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    -DTRURL_WERROR=ON \
    -DTRURL_MANUAL=OFF \
    -DTRURL_TESTS=OFF \
    -DCMAKE_C_FLAGS="${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LDFLAGS} ${LIBS}" \
    || { cat "${_BLDDIR}"/CMakeFiles/CMake*.yaml; false; }
  TZ=UTC cmake --build "${_BLDDIR}" --verbose
  TZ=UTC cmake --install "${_BLDDIR}" --prefix "${_PP}"

  # Manual copy to DESTDIR

  if [ "${CW_MAP}" = '1' ]; then
    cp -p "${_BLDDIR}/${_map_name}" "${_PP}"/bin/
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

  if [ "${CW_TRURL_TEST:-}" = '1' ] && \
     [ "${_RUN_BIN}" != 'true' ]; then
    python3 test.py --runner="${_RUN_BIN}" --trurl="${bin}"
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
