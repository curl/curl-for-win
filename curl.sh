#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# https://cmake.org/cmake/help/latest/manual/cmake-properties.7.html
# https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  [ "${CW_DEV_INCREMENTAL:-}" != '1' ] && rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  readonly _ref='RELEASE-NOTES'

  case "${_HOST}" in
    bsd|mac) unixts="$(TZ=UTC stat -f '%m' "${_ref}")";;
    *)       unixts="$(TZ=UTC stat -c '%Y' "${_ref}")";;
  esac

  export SOURCE_DATE_EPOCH="${unixts}"

  # Build

  options=''
  CFLAGS=''
  CPPFLAGS=''

  LIBS=''
  LDFLAGS=''
  LDFLAGS_BIN="${_LDFLAGS_BIN_GLOBAL}"
  LDFLAGS_LIB=''

  if [[ "${_CONFIG}" != *'main'* ]]; then
    LDFLAGS+=' -v'
  # [ "${_CC}" = 'gcc' ] && LDFLAGS+=' -Wl,--trace'
  fi

  if [ "${_OS}" = 'win' ] && [[ "${_CONFIG}" != *'nounicode'* ]]; then
    options+=' -DENABLE_UNICODE=ON'
  fi

  if [ "${_OS}" = 'win' ]; then
    options+=" -DCMAKE_SHARED_LIBRARY_SUFFIX_C=${_CURL_DLL_SUFFIX}.dll"
    _def_name="libcurl${_CURL_DLL_SUFFIX}.def"
    LDFLAGS_LIB+=" -Wl,--output-def,${_def_name}"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    _map_name_lib="libcurl${_CURL_DLL_SUFFIX}.map"
    _map_name_bin='curl.map'
    if [ "${_OS}" = 'mac' ]; then
      LDFLAGS_LIB+=" -Wl,-map,${_map_name_lib}"
      LDFLAGS_BIN+=" -Wl,-map,${_map_name_bin}"
    else
      LDFLAGS_LIB+=" -Wl,-Map,${_map_name_lib}"
      LDFLAGS_BIN+=" -Wl,-Map,${_map_name_bin}"
    fi
  fi

  # Ugly hack. Everything breaks without this due to the accidental ordering
  # of libs and objects, and offering no universal way to (re)insert libs at
  # specific positions. Linker complains about a missing --end-group, then
  # adds it automatically anyway.
  if [[ "${_CONFIG}" = *'libgroup'* ]] && [ "${_LD}" = 'ld' ]; then
    LDFLAGS+=' -Wl,--start-group'
  fi

  if [ "${_OS}" = 'win' ]; then
    # Link lib dependencies in static mode. Implied by `-static` for curl,
    # but required for libcurl, which would link to shared libs by default.
    LDFLAGS+=' -Wl,-Bstatic'
  fi

  if [[ "${_CONFIG}" = *'werror'* ]]; then
    options+=' -DCURL_WERROR=ON'
  fi

  if [[ "${_CONFIG}" = *'curltests'* ]]; then
    options+=' -DBUILD_TESTING=ON'
  else
    options+=' -DBUILD_TESTING=OFF'
  fi

  options+=' -DBUILD_EXAMPLES=OFF'

  if [[ ! "${_CONFIG}" =~ (zero|bldtst|pico|nano|micro|mini) ]]; then
    options+=' -DUSE_SSLS_EXPORT=ON'
  fi

  # for H2/H3
  if [[ "${_CONFIG}" =~ (zero|bldtst|pico|nano) ]]; then
    options+=' -DCURL_DISABLE_ALTSVC=ON'
  fi

  if [[ "${_CONFIG}" =~ (zero|bldtst) ]] && \
     [[ "${_CONFIG}" = *'osnotls'* ]]; then
    options+=' -DCURL_DISABLE_HSTS=ON'
  fi

  if [[ "${_CONFIG}" =~ (zero|bldtst|pico) ]]; then
    options+=' -DCURL_DISABLE_BASIC_AUTH=ON -DCURL_DISABLE_BEARER_AUTH=ON -DCURL_DISABLE_DIGEST_AUTH=ON -DCURL_DISABLE_KERBEROS_AUTH=ON -DCURL_DISABLE_NEGOTIATE_AUTH=ON -DCURL_DISABLE_AWS=ON'
    options+=' -DCURL_DISABLE_HTTP_AUTH=ON'
    options+=' -DCURL_DISABLE_NTLM=ON'
    options+=' -DCURL_DISABLE_SHA512_256=ON'
    options+=' -DCURL_DISABLE_DICT=ON -DCURL_DISABLE_FILE=ON -DCURL_DISABLE_GOPHER=ON -DCURL_DISABLE_MQTT=ON -DCURL_DISABLE_RTSP=ON -DCURL_DISABLE_SMB=ON -DCURL_DISABLE_TELNET=ON -DCURL_DISABLE_TFTP=ON'
    options+=' -DCURL_DISABLE_IPFS=ON'
    options+=' -DCURL_DISABLE_FTP=ON'
    options+=' -DCURL_DISABLE_POP3=ON -DCURL_DISABLE_SMTP=ON'
    [[ "${_CONFIG}" != *'imap'* ]] && options+=' -DCURL_DISABLE_IMAP=ON'
    if [ "${_OS}" != 'win' ]; then
      options+=' -DCURL_DISABLE_BINDLOCAL=ON'
    else
      options+=' -DCURL_WINDOWS_SSPI=OFF'
    fi
    options+=' -DENABLE_UNIX_SOCKETS=OFF'
    options+=' -DENABLE_WEBSOCKETS=OFF'
    options+=' -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON'
  else
    [[ "${_CONFIG}" = *'noftp'* ]] && options+=' -DCURL_DISABLE_FTP=ON'
    if [ "${_OS}" = 'win' ]; then
      options+=' -DCURL_WINDOWS_SSPI=ON'
    elif [ "${_OS}" != 'mac' ] || [ "${_OSVER}" -ge '1010' ]; then  # On macOS we use the built-in LDAP lib
      options+=' -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON'
    fi
  fi

  if [[ "${_CONFIG}" = *'nocookie'* ]]; then
    options+=' -DCURL_DISABLE_COOKIES=ON'
  fi

  if [[ "${_CONFIG}" = *'nohttp'* ]]; then
    options+=' -DCURL_DISABLE_HTTP=ON'
    options+=' -DCURL_DISABLE_PROXY=ON'
  fi

  if [[ "${_CONFIG}" =~ (zero|bldtst|pico) ]] && \
     [[ "${_CONFIG}" != *'imap'* ]] && \
     [[ "${_CONFIG}" = *'nohttp'* ]]; then
    options+=' -DENABLE_THREADED_RESOLVER=OFF'
    options+=' -DCURL_DISABLE_NETRC=ON'
    options+=' -DENABLE_IPV6=OFF'
    options+=' -DCURL_DISABLE_LIBCURL_OPTION=ON'
    options+=' -DCURL_DISABLE_GETOPTIONS=ON'
    options+=' -DCURL_DISABLE_PARSEDATE=ON'
    options+=' -DCURL_DISABLE_SHUFFLE_DNS=ON'
  else
    options+=' -DENABLE_THREADED_RESOLVER=ON'
  fi

  if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then
    options+=" -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
    options+=" -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
  else
    options+=' -DCURL_ZLIB=OFF'
  fi
  if [[ "${_DEPS}" = *'brotli'* ]] && [ -d "../brotli/${_PP}" ]; then
    options+=' -DCURL_BROTLI=ON'
    options+=" -DBROTLI_INCLUDE_DIR=${_TOP}/brotli/${_PP}/include"
    options+=" -DBROTLIDEC_LIBRARY=${_TOP}/brotli/${_PP}/lib/libbrotlidec.a"
    options+=" -DBROTLICOMMON_LIBRARY=${_TOP}/brotli/${_PP}/lib/libbrotlicommon.a"
  else
    options+=' -DCURL_BROTLI=OFF'
  fi
  if [[ "${_DEPS}" = *'zstd'* ]] && [ -d "../zstd/${_PP}" ]; then
    options+=' -DCURL_ZSTD=ON'
    options+=" -DZSTD_INCLUDE_DIR=${_TOP}/zstd/${_PP}/include"
    options+=" -DZSTD_LIBRARY=${_TOP}/zstd/${_PP}/lib/libzstd.a"
  else
    options+=' -DCURL_ZSTD=OFF'
  fi

  h3=0

  if [ -n "${_OPENSSL}" ] && [ -d "../${_OPENSSL}/${_PP}" ]; then
    # ECH feature requests:
    #   https://github.com/libressl/portable/issues/546
    #   https://github.com/openssl/openssl/pull/22938
    options+=' -DCURL_USE_OPENSSL=ON'
    options+=" -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    options+=' -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON'
    if [ "${_OPENSSL}" = 'boringssl' ] || [ "${_OPENSSL}" = 'awslc' ]; then
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        CPPFLAGS+=" -DCURL_BORINGSSL_VERSION=\\\"${BORINGSSL_VER_}\\\""
        options+=' -DHAVE_BORINGSSL=1 -DHAVE_AWSLC=0'  # fast-track configuration
      else
        options+=' -DHAVE_BORINGSSL=0 -DHAVE_AWSLC=1'  # fast-track configuration
      fi
      options+=' -DUSE_ECH=ON'
      LIBS+=' -lpthread'
    else
      options+=' -DHAVE_BORINGSSL=0 -DHAVE_AWSLC=0'  # fast-track configuration
    fi
    h3=1
    if [ "${_OPENSSL}" != 'libressl' ]; then
      options+=' -DHAVE_LIBRESSL=0 -DHAVE_SSL_SET0_WBIO=1'  # fast-track configuration
    fi
    if [ "${_OPENSSL}" = 'openssl' ]; then
      options+=' -DHAVE_SSL_SET_QUIC_TLS_CBS=1'  # fast-track configuration
    else
      options+=' -DHAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT=1'  # fast-track configuration
    fi
  else
    options+=' -DCURL_USE_OPENSSL=OFF'
  fi

  if [ "${_OS}" = 'win' ]; then
    # fast-track configuration
    options+=' -DHAVE_FILE_OFFSET_BITS=1'

    if [[ "${_CONFIG}" != *'osnotls'* && ("${h3}" = '0' || "${_CONFIG}" = *'noh3'*) ]]; then
      options+=' -DCURL_USE_SCHANNEL=ON'
    else
      options+=' -DCURL_USE_SCHANNEL=OFF'
    fi
  fi

  options+=' -DCURL_DISABLE_SRP=ON'

  if [[ "${_DEPS}" = *'libssh1'* ]] && [ -d "../libssh/${_PPS}" ]; then
    options+=' -DCURL_USE_LIBSSH=ON'
    options+=' -DCURL_USE_LIBSSH2=OFF'
    options+=" -DLIBSSH_INCLUDE_DIR=${_TOP}/libssh/${_PPS}/include"
    options+=" -DLIBSSH_LIBRARY=${_TOP}/libssh/${_PPS}/lib/libssh.a"
    CPPFLAGS+=' -DLIBSSH_STATIC'
  elif [[ "${_DEPS}" = *'libssh2'* ]] && [ -d "../libssh2/${_PPS}" ]; then
    options+=' -DCURL_USE_LIBSSH2=ON'
    options+=' -DCURL_USE_LIBSSH=OFF'
    options+=" -DLIBSSH2_INCLUDE_DIR=${_TOP}/libssh2/${_PPS}/include"
    options+=" -DLIBSSH2_LIBRARY=${_TOP}/libssh2/${_PPS}/lib/libssh2.a"
  else
    options+=' -DCURL_USE_LIBSSH=OFF'
    options+=' -DCURL_USE_LIBSSH2=OFF'
  fi

  if [[ "${_DEPS}" = *'nghttp2'* ]] && [ -d "../nghttp2/${_PP}" ]; then
    options+=' -DUSE_NGHTTP2=ON'
    options+=" -DNGHTTP2_INCLUDE_DIR=${_TOP}/nghttp2/${_PP}/include"
    options+=" -DNGHTTP2_LIBRARY=${_TOP}/nghttp2/${_PP}/lib/libnghttp2.a"
    CPPFLAGS+=' -DNGHTTP2_STATICLIB'
  else
    options+=' -DUSE_NGHTTP2=OFF'
  fi

  if [[ "${h3}" = '1' && \
        "${_DEPS}" = *'nghttp3'* && -d "../nghttp3/${_PP}" && \
        "${_DEPS}" = *'ngtcp2'* && -d "../ngtcp2/${_PPS}" ]]; then
    options+=" -DNGHTTP3_INCLUDE_DIR=${_TOP}/nghttp3/${_PP}/include"
    options+=" -DNGHTTP3_LIBRARY=${_TOP}/nghttp3/${_PP}/lib/libnghttp3.a"
    CPPFLAGS+=' -DNGHTTP3_STATICLIB'

    options+=' -DUSE_NGTCP2=ON'
    options+=" -DNGTCP2_INCLUDE_DIR=${_TOP}/ngtcp2/${_PPS}/include"
    options+=" -DNGTCP2_LIBRARY=${_TOP}/ngtcp2/${_PPS}/lib/libngtcp2.a"
    CPPFLAGS+=' -DNGTCP2_STATICLIB'
  else
    options+=' -DUSE_NGTCP2=OFF'
  fi
  if [[ "${_DEPS}" = *'cares'* ]] && [ -d "../cares/${_PP}" ]; then
    options+=' -DENABLE_ARES=ON'
    options+=" -DCARES_INCLUDE_DIR=${_TOP}/cares/${_PP}/include"
    options+=" -DCARES_LIBRARY=${_TOP}/cares/${_PP}/lib/libcares.a"
    CPPFLAGS+=' -DCARES_STATICLIB'
    options+=' -DUSE_HTTPSRR=ON'
  fi
  if [ "${_OS}" = 'mac' ]; then
    # GSS API deprecated in 2012-2013 (OS X 10.8 Mountain Lion / 10.9 Mavericks, iOS 7.0)
  # options+=' -DCURL_USE_GSSAPI=ON'
    :
  fi

  options+=' -DUSE_LIBIDN2=OFF'
  if [[ ! "${_CONFIG}" =~ (pico|osnoidn) ]]; then
    if [ "${_OS}" = 'win' ]; then
      options+=' -DUSE_WIN32_IDN=ON'
    elif [ "${_OS}" = 'mac' ]; then
      options+=' -DUSE_APPLE_IDN=ON'
    fi
  fi

  if [[ "${_DEPS}" = *'libpsl'* ]] && [ -d "../libpsl/${_PP}" ]; then
    options+=' -DCURL_USE_LIBPSL=ON'
    options+=" -DLIBPSL_INCLUDE_DIR=${_TOP}/libpsl/${_PP}/include"
    options+=" -DLIBPSL_LIBRARY=${_TOP}/libpsl/${_PP}/lib/libpsl.a"
  else
    options+=' -DCURL_USE_LIBPSL=OFF'
  fi

  options+=' -DENABLE_CURL_MANUAL=ON'  # Build and embed manual
  options+=' -DBUILD_LIBCURL_DOCS=OFF'  # Skip building documentation in man page format
  options+=' -DBUILD_MISC_DOCS=OFF'  # Skip building man pages for tools

  if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
    LDFLAGS_BIN+=" -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-bin.tar"
    LDFLAGS_LIB+=" -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dyn.tar"
  fi

  if [ "${_OS}" = 'linux' ] || [ "${_OS}" = 'mac' ]; then
    # We build with -fPIC by default, build lib objects once to save build time.
    options+=' -DSHARE_LIB_OBJECT=ON'
  fi

  if [ "${_OS}" != 'win' ]; then
    # Workaround to suppress warning about unused `CMAKE_RC_FLAGS`.
    # Could not figure how to pass it with an argument with spaces by
    # appending it to `options`, or via the environment.
    #   CMake Warning: Manually-specified variables were not used by the project: CMAKE_RC_FLAGS
    options+=' --no-warn-unused-cli'
  fi

  if [[ "${_CONFIG}" != *'nounity'* ]]; then
    options+=' -DCMAKE_UNITY_BUILD=ON'
    if [[ "${_CONFIG}" =~ (dev|unitybatch) ]]; then
      options+=' -DCMAKE_UNITY_BUILD_BATCH_SIZE=30'
    else
      # Prevent false positive compiler warnings breaking the build when
      # building for linux on mac in single-batch unity mode.
      # Seen with gcc 9.2.0 via filosottile/musl-cross/musl-cross
      if [ "${_HOST}" = 'mac' ] && \
         [ "${_OS}" = 'linux' ] && \
         [ "${_CC}" = 'gcc' ] && \
         [ "${_CRT}" = 'musl' ]; then
        CFLAGS+=' -Wno-error=null-dereference'
      fi
    fi
  fi

  if [[ "${_CONFIG}" = *'prefill'* ]]; then
    options+=' -D_CURL_PREFILL=ON'
  fi

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    options+=' -DBUILD_CURL_EXE=ON'
    options+=' -DBUILD_STATIC_CURL=ON'

    if [ -n "${_OPENSSL}" ]; then
      if [ "${_OS}" = 'mac' ] && [ "${CURL_VER_}" != '8.16.0' ]; then
        options+=' -DUSE_APPLE_SECTRUST=ON'
      else
        if [[ "${_DEPS}" = *'cacert'* ]]; then
          options+=" -DCURL_CA_EMBED=${_TOP}/cacert/${_CACERT}"
        fi

        if [ "${_OS}" = 'win' ]; then
          options+=' -DCURL_CA_SEARCH_SAFE=ON'
        fi
      fi
    fi
  else
    options+=' -DBUILD_CURL_EXE=OFF'
  fi

  patch="${_NAM}${_PATCHSUFFIX}.patch"
  if [ -f "../${patch}" ] && false; then
    # This command requires a git clone deep enough to contain all
    # curl-for-win repo versions pointing the current latest curl release.
    # To retrieve the hash for the commit adding or updating the .patch
    # file (if any). In a shallow clone this could return the latest commit
    # hash, breaking reproducibility.
    hash="$(git -C .. log -1 '--pretty=format:%h' -- "${patch}")"
    if [ -n "${hash}" ]; then
      patchstamp="https://github.com/curl/curl-for-win/blob/${hash}/${patch}"
      # Appearing as: "security patched: https://github.com/curl/curl-for-win/blob/95a0e6df/curl.patch"
      [ -n "${patchstamp}" ] && CPPFLAGS+=" -DCURL_PATCHSTAMP=\\\"${patchstamp}\\\""
    fi
  fi

  if [ "${_OS}" = 'linux' ] && [ "${_CROSS}" = '1' ]; then
    # Auto-detection is disabled for this feature in cross-builds.
    # Ensure it is set as in native builds.
    options+=' -DHAVE_WRITABLE_ARGV=1'
  fi

  options+=' -DCURL_USE_PKGCONFIG=OFF'

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ] || [ ! -d "${_BLDDIR}" ]; then
    # shellcheck disable=SC2086
    cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
      -DCURL_CA_PATH=none \
      -DCURL_CA_BUNDLE=none \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_STATIC_LIBS=ON \
      -DCURL_HIDDEN_SYMBOLS=ON \
      -DCMAKE_RC_FLAGS="${_RCFLAGS_GLOBAL}" \
      -DCMAKE_C_FLAGS="${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${CPPFLAGS} ${_LDFLAGS_GLOBAL}" \
      -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS} ${LDFLAGS_BIN} ${LIBS}" \
      -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS} ${LDFLAGS_LIB} ${LIBS}" \
      || { cat "${_BLDDIR}"/CMakeFiles/CMake*.yaml; false; }
    # --debug-find --debug-trycompile
  fi

  if [[ "${_CONFIG}" != *'nodumpconf'* ]]; then
    grep -a -F '#define' "${_BLDDIR}/lib/curl_config.h" | sort || true
  fi

  TZ=UTC cmake --build "${_BLDDIR}" --verbose
  TZ=UTC cmake --install "${_BLDDIR}" --prefix "${_PP}"

  if [[ "${_CONFIG}" = *'curltests'* ]]; then
    TZ=UTC cmake --build "${_BLDDIR}" --target testdeps
  fi

  [[ "${_CONFIG}" = *'CURLNOPKG'* ]] && exit

  # Manual copy to DESTDIR

  # These custom outputs end up in different directories depending on make tool
  if [ "${_MK}" = 'ninja' ]; then
    _out_lib=''
    _out_src=''
  else
    _out_lib='lib/'
    _out_src='src/'
  fi

  if [ "${_OS}" = 'win' ]; then
    cp -p "${_BLDDIR}/${_out_lib}${_def_name}" "${_PP}"/bin/
  fi

  if [ "${CW_MAP}" = '1' ]; then
    cp -p "${_BLDDIR}/${_out_lib}${_map_name_lib}" "${_PP}/${DYN_DIR}/"
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      cp -p "${_BLDDIR}/${_out_src}${_map_name_bin}" "${_PP}"/bin/
    fi
  fi

  # Make steps for determinism

  # Show the reference timestamp in UTC.
  # shellcheck disable=SC2154
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
     strings "${bin}" | grep -a -F 'curl-for-win' | grep -v -a -E '/blob/[a-f0-9]+/curl(\.[a-z]+)?\.patch$'; then
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
        if [ "${_OPENSSL}" = 'awslc' ]; then
          # FIXME: AWS-LC builds export C++ and AWS-LC symbols
          ../_info-bin.sh --filetype "${filetype}" --is-curl "${f}" || true
        else
          ../_info-bin.sh --filetype "${filetype}" --is-curl "${f}"
        fi
      fi
    done
  done

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    # Execute curl and compiled-in dependency code. This is not secure.
    # It also requires installing WINE on a compatible CPU (and a QEMU setup
    # on non-compatible ones). It would be best to extract `--version` output
    # directly from the binary as strings, but curl creates most of these
    # strings dynamically at runtime, so this is not possible
    # (as of curl 7.83.1).
    out="../curl-version-${_CPUPUB}.txt"
    ${_RUN_BIN} "${bin}" --disable --version | sed 's/\r//g' | tee "${out}"
    [ -s "${out}" ] || rm -f "${out}"
  fi

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}"/docs/examples
  mkdir -p "${_DST}"/docs/libcurl
  mkdir -p "${_DST}"/include/curl
  mkdir -p "${_DST}"/lib
  mkdir -p "${_DST}"/bin

  (
    set +x
    # Copy suffix-less files (not directories), with a .txt suffix added to them
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    for file in docs/libcurl/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    # Copy examples
    cp -f -p docs/examples/*.c                  "${_DST}"/docs/examples/
    cp -f -p docs/examples/Makefile.example     "${_DST}"/docs/examples/
  )
  cp -f -p "${_PP}"/include/curl/*.h          "${_DST}"/include/curl/
  cp -f -a "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"  "${_DST}/${DYN_DIR}"/  # we must not pick up *.dll.a here
  cp -f -p "${_PP}"/lib/*.a                   "${_DST}"/lib/
  if [[ "${_CONFIG}" = *'curldocs'* ]]; then
    mkdir -p "${_DST}"/docs/libcurl/opts
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      mkdir -p "${_DST}"/docs/cmdline-opts
      cp -f -p docs/cmdline-opts/*.md             "${_DST}"/docs/cmdline-opts/
    fi
    cp -f -p docs/libcurl/opts/*.md             "${_DST}"/docs/libcurl/opts/
    cp -f -p docs/libcurl/*.md                  "${_DST}"/docs/libcurl/
  fi
  cp -f -p docs/*.md                          "${_DST}"/docs/
  cp -f -p COPYING                            "${_DST}"/COPYING.txt
  cp -f -p README                             "${_DST}"/README.txt
  cp -f -p RELEASE-NOTES                      "${_DST}"/RELEASE-NOTES.txt

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    cp -f -p "${bin}"                           "${_DST}"/bin/
  fi

  if [ "${_OS}" = 'win' ]; then
    cp -f -p "${_PP}"/bin/*.def                 "${_DST}"/bin/
  fi

  if [ "${_OS}" = 'linux' ]; then
    # To copy these files in addition to `@libcurl.so -> libcurl.so.4`:
    #   @libcurl.so.4 -> libcurl.so.4.8.0
    #    libcurl.so.4.8.0
    rsync --archive "${_PP}/${DYN_DIR}"/*"${DYN_EXT}"* "${_DST}/${DYN_DIR}"/
  fi

  if [ "${CW_MAP}" = '1' ]; then
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      cp -f -p "${_PP}"/bin/curl.map              "${_DST}"/bin/
    fi
    cp -f -p "${_PP}/${DYN_DIR}"/*.map          "${_DST}/${DYN_DIR}"/
  fi

  if [[ "${_DEPS}" = *'cacert'* ]]; then
    cp -f -p scripts/mk-ca-bundle.pl            "${_DST}"/
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
