#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# curl pre-packaging, shared between build systems.

{
  if [ -n "${_OPENSSL}" ]; then
    # Download CA bundle
    calocal='../ca-bundle.crt'
    if [ ! -f "${calocal}" ]; then

      if [ -n "${CACERT_VER}" ]; then
        caremote="cacert-${CACERT_VER}.pem"
      else
         # CAVEAT: Unversioned build-time download. It can break reproducibility.
        caremote='cacert.pem'
      fi

      curl --disable --user-agent '' --fail --silent --show-error \
        --remote-time --xattr \
        --output "${calocal}" \
        "https://curl.se/ca/${caremote}"
    fi

    openssl dgst -sha256 "${calocal}"
  fi

  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_PP}"/bin/*.exe
  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_PP}"/bin/*.dll
  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libcurl.a
  # LLVM strip does not support implibs, but they are deterministic by default:
  #   error: unsupported object file format
  [ "${_LD}" = 'ld' ] && "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libcurl.dll.a

  ../_peclean.py "${_ref}" "${_PP}"/bin/*.exe
  ../_peclean.py "${_ref}" "${_PP}"/bin/*.dll

  ../_sign-code.sh "${_ref}" "${_PP}"/bin/*.exe
  ../_sign-code.sh "${_ref}" "${_PP}"/bin/*.dll

  touch -c -r "${_ref}" "${_PP}"/bin/*.exe
  touch -c -r "${_ref}" "${_PP}"/bin/*.dll
  touch -c -r "${_ref}" "${_PP}"/bin/*.def
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  if [ "${CW_MAP}" = '1' ]; then
    touch -c -r "${_ref}" "${_PP}"/bin/*.map
  fi

  # Tests

  # Show the reference timestamp in UTC.
  case "${_OS}" in
    bsd|mac) TZ=UTC stat -f '%N: %Sm' -t '%Y-%m-%d %H:%M' "${_ref}";;
    *)       TZ=UTC stat --format '%n: %y' "${_ref}";;
  esac

  TZ=UTC "${_OBJDUMP}" --all-headers "${_PP}"/bin/*.exe | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f
  TZ=UTC "${_OBJDUMP}" --all-headers "${_PP}"/bin/*.dll | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f

  # Execute curl and compiled-in dependency code. This is not secure, but
  # the build process already requires executing external code
  # (e.g. configure scripts) on the build machine, so this does not make
  # it worse, except that it requires installing WINE on a compatible CPU
  # (and a QEMU setup on non-compatible ones). It would be best to extract
  # `--version` output directly from the binary as strings, but curl creates
  # most of these strings dynamically at runtime, so this is not possible
  # (as of curl 7.83.1).
  ${_WINE} "${_PP}"/bin/curl.exe --version | tee "curl-${_CPU}.txt"

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

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
  cp -f -p "${_PP}"/include/curl/*.h "${_DST}/include/curl/"
  cp -f -p "${_PP}"/bin/*.exe        "${_DST}/bin/"
  cp -f -p "${_PP}"/bin/*.dll        "${_DST}/bin/"
  cp -f -p "${_PP}"/bin/*.def        "${_DST}/bin/"
  cp -f -p "${_PP}"/lib/*.a          "${_DST}/lib/"
  cp -f -p docs/*.md                 "${_DST}/docs/"
  cp -f -p CHANGES                   "${_DST}/CHANGES.txt"
  cp -f -p COPYING                   "${_DST}/COPYING.txt"
  cp -f -p README                    "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES             "${_DST}/RELEASE-NOTES.txt"

  if [ -n "${_OPENSSL}" ]; then
    cp -f -p scripts/mk-ca-bundle.pl   "${_DST}/"
    cp -f -p "${calocal}"              "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_PP}"/bin/*.map        "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
}
