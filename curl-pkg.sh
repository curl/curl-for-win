#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# curl pre-packaging, shared between build systems.

{
  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_PP}/bin/curl${BIN_EXT}"
  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"
  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libcurl.a
  # LLVM strip does not support implibs, but they are deterministic by default:
  #   error: unsupported object file format
  [ "${_LD}" = 'ld' ] && [ "${_OS}" = 'win' ] && "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libcurl.dll.a

  ../_clean-bin.sh "${_ref}" "${_PP}/bin/curl${BIN_EXT}"
  ../_clean-bin.sh "${_ref}" "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"

  ../_sign-code.sh "${_ref}" "${_PP}/bin/curl${BIN_EXT}"
  ../_sign-code.sh "${_ref}" "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"

  touch -c -r "${_ref}" "${_PP}/bin/curl${BIN_EXT}"
  touch -c -r "${_ref}" "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  if [ "${CW_MAP}" = '1' ] && [ "${_OS}" != 'mac' ]; then
    touch -c -r "${_ref}" "${_PP}"/bin/*.map
    touch -c -r "${_ref}" "${_PP}/${DYN_DIR}"/*.map
  fi

  # Tests

  # Show the reference timestamp in UTC.
  case "${_HOSTOS}" in
    bsd|mac) TZ=UTC stat -f '%N: %Sm' -t '%Y-%m-%d %H:%M' "${_ref}";;
    *)       TZ=UTC stat --format='%n: %y' "${_ref}";;
  esac

  for suffix in exe dyn; do
    {
      if [ "${suffix}" = 'exe' ]; then
        echo "${_PP}/bin/curl${BIN_EXT}"
      else
        find "${_PP}/${DYN_DIR}" -name "*${DYN_EXT}" | sort
      fi
    } | while read -r f; do

      if [ "${_OS}" = 'win' ]; then
        TZ=UTC "${_OBJDUMP}" --all-headers "${f}" | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f
        # Verify exported curl symbols
        if [ "${suffix}" = 'exe' ]; then
          "${_OBJDUMP}" --all-headers "${f}" | grep -a -F ' curl_' && false  # should not have any hits for statically linked curl
        else
          "${_OBJDUMP}" --all-headers "${f}" | grep -a -F ' curl_' || false  # show public libcurl APIs (in a well-defined order)
        fi
        # Dump 'DllCharacteristics' flags, e.g. HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, GUARD_CF, TERMINAL_SERVICE_AWARE
        "${_OBJDUMP}" --all-headers "${f}" | grep -a -E -o '^\s+[A-Z_]{4,}$' | sort
        # Dump cfguard load configuration flags
        if [ "${_CC}" = 'llvm' ]; then  # binutils readelf (as of v2.40) does not recognize this option
          # CF_FUNCTION_TABLE_PRESENT, CF_INSTRUMENTED, CF_LONGJUMP_TABLE_PRESENT (optional)
          "${_READELF}" --coff-load-config "${f}" | grep -a -E 'CF_[A-Z_]' | sort
        fi
      elif [ "${_OS}" = 'mac' ]; then
        otool -L "${f}"
      elif [ "${_OS}" = 'linux' ]; then
        "${_READELF}" --file-header --dynamic "${f}"
      fi
    done
  done

  # Execute curl and compiled-in dependency code. This is not secure, but
  # the build process already requires executing external code
  # (e.g. configure scripts) on the build machine, so this does not make
  # it worse, except that it requires installing WINE on a compatible CPU
  # (and a QEMU setup on non-compatible ones). It would be best to extract
  # `--version` output directly from the binary as strings, but curl creates
  # most of these strings dynamically at runtime, so this is not possible
  # (as of curl 7.83.1).
  ${_WINE} "${_PP}/bin/curl${BIN_EXT}" --version | tee "curl-${_CPU}.txt"

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(realpath _pkg)"; rm -r -f "${_DST}"

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
  )
  cp -f -p "${_PP}"/include/curl/*.h         "${_DST}/include/curl/"
  cp -f -p "${_PP}/bin/curl${BIN_EXT}"       "${_DST}/bin/"
  cp -f -a "${_PP}/${DYN_DIR}"/*"${DYN_EXT}" "${_DST}/${DYN_DIR}/"
  cp -f -p "${_PP}"/lib/*.a                  "${_DST}/lib/"
  cp -f -p docs/*.md                         "${_DST}/docs/"
  cp -f -p CHANGES                           "${_DST}/CHANGES.txt"
  cp -f -p COPYING                           "${_DST}/COPYING.txt"
  cp -f -p README                            "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES                     "${_DST}/RELEASE-NOTES.txt"

  if [ "${_OS}" = 'win' ]; then
    cp -f -p "${_PP}"/bin/*.def                "${_DST}/bin/"
  fi

  if [ "${CW_MAP}" = '1' ] && [ "${_OS}" != 'mac' ]; then
    cp -f -p "${_PP}"/bin/curl.map             "${_DST}/bin/"
    cp -f -p "${_PP}/${DYN_DIR}"/*.map         "${_DST}/${DYN_DIR}/"
  fi

  if [ -d ../cacert ]; then
    cp -f -p scripts/mk-ca-bundle.pl           "${_DST}/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
}
