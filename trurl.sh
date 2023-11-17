#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}"

  # Build

  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LDLIBS=''

  if [[ "${_CONFIG}" != *'main'* ]]; then
    LDFLAGS+=' -v'
  # [ "${_CC}" = 'gcc' ] && LDFLAGS+=' -Wl,--trace'
  fi

  if [ "${CW_MAP}" = '1' ]; then
    map_name='trurl.map'
    if [ "${_OS}" = 'mac' ]; then
      LDFLAGS+=" -Wl,-map,${map_name}"
    else
      LDFLAGS+=" -Wl,-Map,${map_name}"
    fi
  fi

  CPPFLAGS+=" -I../curl/${_PP}/include"
  if [[ "${_CONFIG}" = *'zero'* ]]; then
    # link statically in 'zero' (no external dependencies) config
    LDLIBS+=' ../curl/${_PP}/lib/libcurl.a'
    if [ "${_OS}" = 'win' ]; then
      CPPFLAGS+=' -DCURL_STATICLIB'
      LDLIBS+=' -lws2_32 -lcrypt32 -lbcrypt'
    elif [ "${_OS}" = 'mac' ]; then
      if [[ "${_CONFIG}" != *'osnotls'* ]]; then
        LDLIBS+=' -framework Security'
      fi
      LDLIBS+=' -framework SystemConfiguration'
    elif [ "${_OS}" = 'linux' ]; then
      LDFLAGS+=' -static'
    fi
  else
    LDFLAGS+=" -L../curl/${_PP}/lib"
    LDLIBS+=' -lcurl'
  fi

  if [ "${TRURL_VER_}" = '0.9' ]; then
    LDFLAGS+=" ${LDLIBS}"
    # Add dummy curl-config to avoid picking up any system default and
    # linking to it instead of using our build.
    echo '#!/bin/sh' > ./curl-config
    chmod +x ./curl-config
    export PATH; PATH="$(pwd):${PATH}"
  fi

  "${_MAKE}" clean
  "${_MAKE}" NDEBUG=1 TRURL_IGNORE_CURL_CONFIG=1

  if [ "${_OS}" = 'mac' ]; then
    install_name_tool -change \
      '@rpath/libcurl.4.dylib' \
      '@executable_path/../lib/libcurl.4.dylib' "./trurl${BIN_EXT}"
  fi

  # Install manually

  mkdir -p "${_PP}/bin"

  cp -f -p "./trurl${BIN_EXT}" "${_PP}/bin/"
  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "./${map_name}" "${_PP}/bin/"
  fi

  # Make steps for determinism

  readonly _ref='RELEASE-NOTES'

  bin="${_PP}/bin/trurl${BIN_EXT}"

  # shellcheck disable=SC2086
  "${_STRIP_BIN}" ${_STRIPFLAGS_BIN} "${bin}"

  ../_clean-bin.sh "${_ref}" "${bin}"

  ../_sign-code.sh "${_ref}" "${bin}"

  touch -c -r "${_ref}" "${bin}"

  ../_info-bin.sh --filetype 'exe' "${bin}"

  # Execute curl and compiled-in dependency code. This is not secure.
  [ "${_OS}" = 'win' ] && cp -p "../curl/${_PP}/bin/"*"${DYN_EXT}" .
  # On macOS this picks up a system libcurl. Ours is picked up
  # when running it from the unpacked release tarball.
  LD_LIBRARY_PATH="$(pwd)/../curl/${_PP}/lib" ${_RUN_BIN} "${bin}" --version | tee "trurl-${_CPU}.txt" || true

  if [ "${CW_TURL_TEST:-}" = '1' ] && \
     [ "${_RUN_BIN}" != 'echo' ]; then
    python3 ./test.py "--runner=${_RUN_BIN}" "--trurl=${bin}"
  fi

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/bin"

  cp -f -p "${bin}"       "${_DST}/bin/"
  cp -f -p COPYING        "${_DST}/COPYING.txt"
  cp -f -p README.md      "${_DST}/README.md"
  cp -f -p RELEASE-NOTES  "${_DST}/RELEASE-NOTES.txt"

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_PP}/bin/${map_name}"  "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
