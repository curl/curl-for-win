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

  # Always delete targets, including ones made for a different CPU.
  find . -name '*.o' -delete
  find . -name "trurl${BIN_EXT}" -delete

  rm -r -f "${_PKGDIR:?}"

  # Build

  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LDLIBS="${_LIBS_GLOBAL}"

  [ "${_CONFIG#*main*}" = "${_CONFIG}" ] && LDFLAGS+=' -v'

  CPPFLAGS+=" -I../curl/${_PP}/include"
  if [ "${_CONFIG#*zero*}" != "${_CONFIG}" ]; then
    CPPFLAGS+=" -DCURL_STATICLIB"
    if [ "${_OS}" = 'mac' ]; then
      LDFLAGS+=' -static'
    else
      LDFLAGS+=' -Wl,-Bstatic'
      LDLIBS+=' -Wl,-Bstatic'
    fi
    if [ "${_OS}" = 'win' ]; then
      LDLIBS+=' -lws2_32 -lcrypt32 -lbcrypt'
    fi
  else
    if [ "${_OS}" = 'mac' ]; then
      LDFLAGS+=' -dynamic'
    else
      LDFLAGS+=' -Wl,-Bdynamic'
      LDLIBS+=' -Wl,-Bdynamic'
    fi
  fi
  LDFLAGS+=" -L../curl/${_PP}/lib"
  LDLIBS+=' -lcurl'

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

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/bin"

  cp -f -p "${bin}"       "${_DST}/bin/"
  cp -f -p COPYING        "${_DST}/COPYING.txt"
  cp -f -p README.md      "${_DST}/README.md"
  cp -f -p RELEASE-NOTES  "${_DST}/RELEASE-NOTES.txt"

  ../_pkg.sh "$(pwd)/${_ref}"
)
