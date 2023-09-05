#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# curl pre-packaging, shared between build systems.

{
  # Make steps for determinism

  readonly _ref='CHANGES'

  # Show the reference timestamp in UTC.
  case "${_HOSTOS}" in
    bsd|mac) TZ=UTC stat -f '%N: %Sm' -t '%Y-%m-%d %H:%M' "${_ref}";;
    *)       TZ=UTC stat -c '%n: %y' "${_ref}";;
  esac

  # Process libcurl static library

  # shellcheck disable=SC2086
  "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libcurl.a
  # LLVM strip does not support implibs, but they are deterministic by default:
  #   error: unsupported object file format
  if [ "${_LD}" = 'ld' ] && [ "${_OS}" = 'win' ]; then
    # shellcheck disable=SC2086
    "${_STRIP}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libcurl.dll.a
  fi

  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Process map files

  if [ "${CW_MAP}" = '1' ]; then
    touch -c -r "${_ref}" "${_PP}"/bin/*.map
    touch -c -r "${_ref}" "${_PP}/${DYN_DIR}"/*.map
  fi

  # Process curl tool and libcurl shared library

  for suffix in exe dyn; do
    {
      if [ "${suffix}" = 'exe' ]; then
        echo "${_PP}/bin/curl${BIN_EXT}"
      else
        find "${_PP}/${DYN_DIR}" -name "*${DYN_EXT}*" -a -not -name '*.dll.a' | sort
      fi
    } | while read -r f; do

      if [ ! -L "${f}" ]; then
        if [ "${suffix}" = 'exe' ]; then
          # shellcheck disable=SC2086
          "${_STRIP}" ${_STRIPFLAGS_BIN} "${f}"
        else
          # shellcheck disable=SC2086
          "${_STRIP}" ${_STRIPFLAGS_DYN} "${f}"
        fi

        ../_clean-bin.sh "${_ref}" "${f}"

        ../_sign-code.sh "${_ref}" "${f}"
      fi

      touch -h -r "${_ref}" "${f}"

      # Tests

      if [ ! -L "${f}" ]; then
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
          _prefix=''
          [ "${_TOOLCHAIN}" = 'llvm-apple' ] || _prefix='llvm-'
          TZ=UTC "${_prefix}objdump" --arch=all --private-headers "${f}" | grep -a -i -F 'magic'
          # -dyld_info ignored by llvm-otool as of v16.0.6
          TZ=UTC "${_prefix}otool" -arch all -f -v -L -dyld_info "${f}"
          # Display `LC_BUILD_VERSION` / `LC_VERSION_MIN_MACOSX` info
          TZ=UTC "${_prefix}otool" -arch all -f -l "${f}" | grep -a -w -E '(\(architecture|^ *(minos|version|sdk))'
        elif [ "${_OS}" = 'linux' ]; then
          "${_READELF}" --file-header --dynamic "${f}"
          if command -v checksec >/dev/null 2>&1; then
            if [ "${_DIST}" = 'alpine' ]; then
              checksec --json --file "${f}" | jq  # checksec-rs
            else
              checksec --format=json --file="${f}" | jq
              checksec --format=xml --fortify-file="${f}"  # duplicate keys in json, cannot apply jq
            fi
          fi
          # Show linked GLIBC versions
          # https://en.wikipedia.org/wiki/Glibc#Version_history
          if [ "${_CPU}" = 'a64' ]; then
            filter='@GLIBC_2\.(17|2[0-9])$'  # Exclude: 2.17 (2012-12) and 2.2x (2019-02)
          else
            filter='@GLIBC_([0-9]+\.[0-9]+\.[0-9]+|2\.([0-9]|1[0-9]))$'  # Exclude: x.y.z, 2.x, 2.1x (-2014-02)
          fi
          "${NM}" --dynamic --undefined-only "${f}" \
            | grep -E -v "${filter}" \
            | grep -E -o '@GLIBC_[0-9]+\.[0-9]+$' | sed 's/@GLIBC_//g' | sort -u -V || true
          "${NM}" --dynamic --undefined-only "${f}" \
            | grep -F '@GLIBC_' | grep -E -v "${filter}" || true
        fi
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
  ${_RUN_BIN} "${_PP}/bin/curl${BIN_EXT}" --version | tee "curl-${_CPU}.txt"

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

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
  cp -f -p "${_PP}"/include/curl/*.h          "${_DST}/include/curl/"
  cp -f -p "${_PP}/bin/curl${BIN_EXT}"        "${_DST}/bin/"
  cp -f -a "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"  "${_DST}/${DYN_DIR}/"  # we must not pick up *.dll.a here
  cp -f -p "${_PP}"/lib/*.a                   "${_DST}/lib/"
  cp -f -p docs/*.md                          "${_DST}/docs/"
  cp -f -p CHANGES                            "${_DST}/CHANGES.txt"
  cp -f -p COPYING                            "${_DST}/COPYING.txt"
  cp -f -p README                             "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES                      "${_DST}/RELEASE-NOTES.txt"

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
    cp -f -p "${_PP}"/bin/curl.map              "${_DST}/bin/"
    cp -f -p "${_PP}/${DYN_DIR}"/*.map          "${_DST}/${DYN_DIR}/"
  fi

  if [ -d ../cacert ]; then
    cp -f -p scripts/mk-ca-bundle.pl            "${_DST}/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
}
