#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# curl pre-packaging, shared between build systems.

{
  # Make steps for determinism

  readonly _ref='CHANGES'

  # Show the reference timestamp in UTC.
  case "${_HOST}" in
    bsd|mac) TZ=UTC stat -f '%N: %Sm' -t '%Y-%m-%d %H:%M' "${_ref}";;
    *)       TZ=UTC stat -c '%n: %y' "${_ref}";;
  esac

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    bin="${_PP}/bin/curl${BIN_EXT}"
  else
    bin=''
  fi

  # Extra checks (do this before code signing)

  if [[ "${_CONFIG}" != *'nocurltool'* ]] && \
     strings "${bin}" | grep -a -F 'curl-for-win'; then
    echo "! Error: Our project root path is leaking into the binary: '${bin}'"
    exit 1
  fi

  # Process libcurl static library

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libcurl.a
  # LLVM strip does not support implibs, but they are deterministic by default:
  #   error: unsupported object file format
  if [ "${_LD}" = 'ld' ] && [ "${_OS}" = 'win' ]; then
    # shellcheck disable=SC2086
    "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libcurl.dll.a
  fi

  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  if [ "${_OS}" = 'win' ]; then
    touch -c -r "${_ref}" "${_PP}"/bin/*.def
  fi

  # Process map files

  if [ "${CW_MAP}" = '1' ]; then
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      touch -c -r "${_ref}" "${_PP}"/bin/curl.map
    fi
    touch -c -r "${_ref}" "${_PP}/${DYN_DIR}"/*.map
  fi

  # Process curl tool and libcurl shared library

  for filetype in 'exe' 'dyn'; do
    [ "${filetype}" = 'exe' ] && [[ "${_CONFIG}" = *'nocurltool'* ]] && continue
    {
      if [ "${filetype}" = 'exe' ]; then
        echo "${bin}"
      else
        find "${_PP}/${DYN_DIR}" -name "*${DYN_EXT}*" -a -not -name '*.dll.a' | sort
      fi
    } | while read -r f; do

      if [ ! -L "${f}" ]; then
        if [ "${filetype}" = 'exe' ]; then
          # shellcheck disable=SC2086
          "${_STRIP_BIN}" ${_STRIPFLAGS_BIN} "${f}"
        else
          # shellcheck disable=SC2086
          "${_STRIP_BIN}" ${_STRIPFLAGS_DYN} "${f}"
        fi

        ../_clean-bin.sh "${_ref}" "${f}"

        ../_sign-code.sh "${_ref}" "${f}"
      fi

      touch -h -r "${_ref}" "${f}"

      # Tests

      if [ ! -L "${f}" ]; then
        ../_info-bin.sh --filetype "${filetype}" --is-curl "${f}"
      fi
    done
  done

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    # Execute curl and compiled-in dependency code. This is not secure, but
    # the build process already requires executing external code
    # (e.g. configure scripts) on the build machine, so this does not make
    # it worse, except that it requires installing WINE on a compatible CPU
    # (and a QEMU setup on non-compatible ones). It would be best to extract
    # `--version` output directly from the binary as strings, but curl creates
    # most of these strings dynamically at runtime, so this is not possible
    # (as of curl 7.83.1).
    ${_RUN_BIN} "${bin}" --disable --version | tee "curl-${_CPU}.txt" || true
  fi

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/docs/examples"
  mkdir -p "${_DST}/docs/libcurl/opts"
  mkdir -p "${_DST}/include/curl"
  mkdir -p "${_DST}/lib"
  mkdir -p "${_DST}/bin"

  (
    set +x
    for file in docs/*; do
      # Exclude `Makefile`, necessary for autotools builds.
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    for file in docs/libcurl/*; do
      # Exclude `Makefile`, necessary for autotools builds.
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    # Copy simple examples
    tr -d '\r' < docs/examples/Makefile.inc | tr '\n' '^' | sed 's/\\^//g' | tr '^' '\n' \
      | grep 'check_PROGRAMS' | grep -a -o -E '=.+$' | cut -c 2- \
      | sed -E 's/ +/ /g' | tr ' ' '\n' | while read -r f; do
      [ -n "${f}" ] && cp -f -p "docs/examples/${f}.c" "${_DST}/docs/examples/"
    done
  )
  cp -f -p "${_PP}"/include/curl/*.h          "${_DST}/include/curl/"
  cp -f -a "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"  "${_DST}/${DYN_DIR}/"  # we must not pick up *.dll.a here
  cp -f -p "${_PP}"/lib/*.a                   "${_DST}/lib/"
  cp -f -p docs/*.md                          "${_DST}/docs/"
  cp -f -p CHANGES                            "${_DST}/CHANGES.txt"
  cp -f -p COPYING                            "${_DST}/COPYING.txt"
  cp -f -p README                             "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES                      "${_DST}/RELEASE-NOTES.txt"

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    cp -f -p "${bin}"                           "${_DST}/bin/"
  fi

  if [ "${_OS}" = 'win' ]; then
    cp -f -p "${_PP}"/bin/*.def                 "${_DST}/bin/"
  fi

  if [ "${_OS}" = 'linux' ]; then
    # To copy these files in addition to `@libcurl.so -> libcurl.so.4`:
    #   @libcurl.so.4 -> libcurl.so.4.8.0
    #    libcurl.so.4.8.0
    rsync --archive "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"* "${_DST}/${DYN_DIR}/"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      cp -f -p "${_PP}"/bin/curl.map              "${_DST}/bin/"
    fi
    cp -f -p "${_PP}/${DYN_DIR}"/*.map          "${_DST}/${DYN_DIR}/"
  fi

  if [[ "${_DEPS}" = *'cacert'* ]]; then
    cp -f -p scripts/mk-ca-bundle.pl            "${_DST}/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
}
