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
  export CFLAGS="${_CFLAGS_GLOBAL} ${_CFLAGS_GLOBAL_RAW}"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LDLIBS=''
  options='TRURL_IGNORE_CURL_CONFIG=1'

  if [[ "${_CONFIG}" != *'debug'* ]]; then
    options+=' NDEBUG=1'
  fi

  # musl-debian-gcc issues
  # https://github.com/curl/curl-for-win/actions/runs/7095411627/job/19312285992
  CFLAGS="${CFLAGS//-fvisibility=hidden/}"

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
    LDLIBS+=" ../curl/${_PP}/lib/libcurl.a"
    if [ "${_OS}" = 'win' ]; then
      CPPFLAGS+=' -DCURL_STATICLIB'
      LDLIBS+=' -lws2_32 -liphlpapi -lcrypt32 -lbcrypt'
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

  "${_MAKE}" clean
  # shellcheck disable=SC2086
  "${_MAKE}" ${options}

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
  if [ "${CW_MAP}" = '1' ]; then
    touch -c -r "${_ref}" "${_PP}/bin/${map_name}"
  fi

  ../_info-bin.sh --filetype 'exe' "${bin}"

  # Execute curl and compiled-in dependency code. This is not secure.
  [ "${_OS}" = 'win' ] && cp -p "../curl/${_PP}/bin/"*"${DYN_EXT}" .
  if [ "${_OS}" = 'linux' ] && [ "${_HOST}" = 'linux' ]; then
    # https://www.man7.org/training/download/shlib_dynlinker_slides.pdf
    export LD_DEBUG='libs,versions,statistics'
  fi
  # On macOS this picks up a system libcurl by default. Ours is picked up
  # when running it from the unpacked release tarball.
  out="../trurl-version-${_CPUPUB}.txt"
  LD_LIBRARY_PATH="$(pwd)/../curl/${_PP}/lib" \
  DYLD_LIBRARY_PATH="$(pwd)/../curl/${_PP}/lib" \
    ${_RUN_BIN} "${bin}" --version | sed 's/\r//g' | tee "${out}" || true
  unset LD_DEBUG
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
    cp -f -p "${_PP}/bin/${map_name}"  "${_DST}"/bin/
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
