#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# https://cmake.org/cmake/help/latest/manual/cmake-properties.7.html
# https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  rm -r -f "${_PKGDIR}" "${_BLDDIR}-shared" "${_BLDDIR}-static"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Set OS string to the autotools value. To test reproducibility across make systems.
  if [ -n "${CW_DEV_FIXUP_OS_STRING:-}" ]; then
    # Windows-* ->
    # shellcheck disable=SC2016
    sed -i.bak 's|set(OS "\\"${CMAKE_SYSTEM_NAME}${CURL_OS_SUFFIX}\\"")|set(OS \\"x86_64-w64-mingw32\\")|g' ./CMakeLists.txt
  fi

  # Build

  # Generate .def file for libcurl by parsing curl headers. Useful to export
  # the libcurl function meant to be exported.
  # Without this, the default linker logic kicks in, whereas it exports every
  # public function, if none is marked for export explicitly. This leads to
  # exporting every libcurl public function, as well as any other ones from
  # statically linked dependencies, resulting in a larger .dll, an inflated
  # implib and a non-standard list of exported functions.
  echo 'EXPORTS' > libcurl.def
  {
    # CURL_EXTERN CURLcode curl_easy_send(CURL *curl, const void *buffer,
    grep -a -h '^CURL_EXTERN ' include/curl/*.h | grep -a -h -F '(' \
      | sed 's/CURL_EXTERN \([a-zA-Z_\* ]*\)[\* ]\([a-z_]*\)(\(.*\)$/\2/g'
    # curl_easy_option_by_name(const char *name);
    grep -a -h -E '^ *\*? *[a-z_]+ *\(.+\);$' include/curl/*.h \
      | sed -E 's|^ *\*? *([a-z_]+) *\(.+$|\1|g'
  } | grep -a -v '^$' | sort | tee -a libcurl.def

  # CMake cannot build everything in one pass. With BUILD_SHARED_LIBS enabled,
  # it does not build a static lib, and links curl.exe against libcurl DLL
  # with no option to change this. We need to split it into two passes. This
  # is be slower than when using a single pass (like in Makefile.m32), but
  # there is no other way. The two passes are:
  #   1. build the shared libcurl DLL + implib + .def
  #   2. build the static libcurl lib + statically linked curl EXE
  for pass in shared static; do

    _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -W -Wall"

    _CFLAGS="${_CFLAGS} -DHAVE_STRCASECMP -DHAVE_STRTOK_R -DHAVE_FTRUNCATE -DHAVE_GETADDRINFO_THREADSAFE"
    _CFLAGS="${_CFLAGS} -DHAVE_SIGNAL -DHAVE_SOCKADDR_IN6_SIN6_SCOPE_ID"
    _CFLAGS="${_CFLAGS} -DHAVE_UNISTD_H"
    _CFLAGS="${_CFLAGS} -DUSE_HEADERS_API"

    options=''

    _LDFLAGS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
    _LDFLAGS_EXE=''
    _LDFLAGS_DLL=''
    if [ "${_CPU}" = 'x86' ]; then
      _CFLAGS="${_CFLAGS} -D_WIN32_WINNT=0x0501 -DHAVE_ATOMIC"  # For Windows XP compatibility
      _LDFLAGS_EXE="${_LDFLAGS_EXE} -Wl,--pic-executable,-e,_mainCRTStartup"
    else
      _CFLAGS="${_CFLAGS} -DHAVE_INET_NTOP -DHAVE_STRUCT_POLLFD"
      _LDFLAGS_EXE="${_LDFLAGS_EXE} -Wl,--pic-executable,-e,mainCRTStartup"
      _LDFLAGS_DLL="${_LDFLAGS_DLL} -Wl,--image-base,0x150000000"
      _LDFLAGS="${_LDFLAGS} -Wl,--high-entropy-va"
    fi

    options="${options} -DCURL_OS_SUFFIX=-${_CPU}"

    # Disabled till we flesh out UNICODE support and document it enough to be
    # safe to use.
  # options="${options} -DENABLE_UNICODE=ON"

    CURL_DLL_SUFFIX=''
    [ "${_CPU}" = 'x64' ] && CURL_DLL_SUFFIX="-${_CPU}"
    [ "${_CPU}" = 'a64' ] && CURL_DLL_SUFFIX="-${_CPU}"

    if [ "${pass}" = 'shared' ]; then
      # CMAKE_SHARED_LIBRARY_SUFFIX is ignored.
      options="${options} -DCMAKE_SHARED_LIBRARY_SUFFIX_C=${CURL_DLL_SUFFIX}.dll"
      _DEF_NAME="libcurl${CURL_DLL_SUFFIX}.def"
      _LDFLAGS_DLL="${_LDFLAGS_DLL} -Wl,--output-def,${_DEF_NAME}"
    fi

    if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
      if [ "${pass}" = 'shared' ]; then
        _MAP_NAME="libcurl${CURL_DLL_SUFFIX}.map"
        _LDFLAGS_DLL="${_LDFLAGS_DLL} -Wl,-Map,${_MAP_NAME}"
      else
        _MAP_NAME='curl.map'
        _LDFLAGS_EXE="${_LDFLAGS_EXE} -Wl,-Map,${_MAP_NAME}"
      fi
    fi

    # Ugly hack. Everything breaks without this due to the accidental ordering of
    # libs and objects, and offering no universal way to (re)insert libs at
    # specific positions. Linker complains about a missing --end-group, then adds
    # it automatically anyway. Same with '-fuse-ld=lld'.
    _LDFLAGS="${_LDFLAGS} -Wl,--start-group"

    _LDFLAGS_DLL="${_LDFLAGS_DLL} $(pwd)/libcurl.def"

    if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ] || \
       [ ! "${_BRANCH#*nano*}" = "${_BRANCH}" ]; then
      options="${options} -DCURL_DISABLE_ALTSVC=ON"
    fi

    if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} -DCURL_DISABLE_CRYPTO_AUTH=1"
      options="${options} -DCURL_DISABLE_DICT=1 -DCURL_DISABLE_FILE=1 -DCURL_DISABLE_GOPHER=1 -DCURL_DISABLE_MQTT=1 -DCURL_DISABLE_RTSP=1 -DCURL_DISABLE_SMB=1 -DCURL_DISABLE_TELNET=1 -DCURL_DISABLE_TFTP=1"
      options="${options} -DCURL_DISABLE_FTP=1"
      options="${options} -DCURL_DISABLE_IMAP=1 -DCURL_DISABLE_POP3=1 -DCURL_DISABLE_SMTP=1"
      options="${options} -DCURL_DISABLE_LDAP=1 -DCURL_DISABLE_LDAPS=1"
    else
      [ "${_BRANCH#*noftp*}" != "${_BRANCH}" ] && _CFLAGS="${_CFLAGS} -DCURL_DISABLE_FTP=1"

      _CFLAGS="${_CFLAGS} -DHAVE_LDAP_SSL"
      _LDFLAGS="${_LDFLAGS} -lwldap32"
    fi

    if [ -d ../zlib ]; then
      options="${options} -DUSE_ZLIB=ON"
      options="${options} -DZLIB_LIBRARY=${_TOP}/zlib/${_PP}/lib/libz.a"
      options="${options} -DZLIB_INCLUDE_DIR=${_TOP}/zlib/${_PP}/include"
    else
      options="${options} -DUSE_ZLIB=OFF"
    fi
    if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
      options="${options} -DCURL_BROTLI=ON"
      options="${options} -DBROTLIDEC_LIBRARY=${_TOP}/brotli/${_PP}/lib/libbrotlidec.a"
      options="${options} -DBROTLICOMMON_LIBRARY=${_TOP}/brotli/${_PP}/lib/libbrotlicommon.a"
      options="${options} -DBROTLI_INCLUDE_DIR=${_TOP}/brotli/${_PP}/include"
    else
      options="${options} -DCURL_BROTLI=OFF"
    fi

    if [ -d ../libressl ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/libressl/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/libressl/${_PP}/include"
    elif [ -d ../openssl-quic ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/openssl-quic/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/openssl-quic/${_PP}/include"
    elif [ -d ../openssl ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/openssl/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/openssl/${_PP}/include"
    else
      options="${options} -DCURL_USE_OPENSSL=OFF"
    fi
    if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
      options="${options} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON"
      _CFLAGS="${_CFLAGS} -DHAVE_OPENSSL_SRP -DUSE_TLS_SRP"
      _LDFLAGS="${_LDFLAGS} -lbcrypt"
    fi

    options="${options} -DCURL_USE_SCHANNEL=ON"
    _CFLAGS="${_CFLAGS} -DHAS_ALPN"

    if [ -d ../libssh2 ]; then
      options="${options} -DCURL_USE_LIBSSH2=ON"
      options="${options} -DLIBSSH2_LIBRARY=${_TOP}/libssh2/${_PP}/lib/libssh2.a"
      options="${options} -DLIBSSH2_INCLUDE_DIR=${_TOP}/libssh2/${_PP}/include"
      _LDFLAGS="${_LDFLAGS} -lbcrypt"
    else
      options="${options} -DCURL_USE_LIBSSH2=OFF"  # Avoid detecting a copy on the host OS
    fi

    if [ -d ../nghttp2 ]; then
      options="${options} -DUSE_NGHTTP2=ON"
      options="${options} -DNGHTTP2_LIBRARY=${_TOP}/nghttp2/${_PP}/lib/libnghttp2.a"
      options="${options} -DNGHTTP2_INCLUDE_DIR=${_TOP}/nghttp2/${_PP}/include"
      _CFLAGS="${_CFLAGS} -DNGHTTP2_STATICLIB"
    else
      options="${options} -DUSE_NGHTTP2=OFF"
    fi
    if [ -d ../nghttp3 ] && [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
      options="${options} -DUSE_NGHTTP3=ON"
      options="${options} -DNGHTTP3_LIBRARY=${_TOP}/nghttp3/${_PP}/lib/libnghttp3.a"
      options="${options} -DNGHTTP3_INCLUDE_DIR=${_TOP}/nghttp3/${_PP}/include"
      _CFLAGS="${_CFLAGS} -DNGHTTP3_STATICLIB"

      options="${options} -DUSE_NGTCP2=ON"
      options="${options} -DNGTCP2_LIBRARY=${_TOP}/ngtcp2/${_PP}/lib/libngtcp2.a"
      options="${options} -DNGTCP2_INCLUDE_DIR=${_TOP}/ngtcp2/${_PP}/include"
      options="${options} -DCMAKE_LIBRARY_PATH=${_TOP}/ngtcp2/${_PP}/lib"
      _CFLAGS="${_CFLAGS} -DNGTCP2_STATICLIB"
      _LDFLAGS="${_LDFLAGS} -lws2_32"  # Necessary for 'CheckQuicSupportInOpenSSL'
    else
      options="${options} -DUSE_NGHTTP3=OFF"
      options="${options} -DUSE_NGTCP2=OFF"
    fi
    if [ -d ../libgsasl ]; then
      _CFLAGS="${_CFLAGS} -DUSE_GSASL -I${_TOP}/libgsasl/${_PP}/include"
      _LDFLAGS="${_LDFLAGS} -L${_TOP}/libgsasl/${_PP}/lib -lgsasl"
    fi
    if [ -d ../libidn2 ]; then  # Also for Windows XP compatibility
      options="${options} -DUSE_LIBIDN2=ON"
      _CFLAGS="${_CFLAGS} -I${_TOP}/libidn2/${_PP}/include"
      _LDFLAGS="${_LDFLAGS} -L${_TOP}/libidn2/${_PP}/lib -lidn2"
    elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} -DUSE_LIBIDN2=OFF"
      options="${options} -DUSE_WIN32_IDN=ON"
    fi

    options="${options} -DENABLE_MANUAL=ON"  # Does not seem to work.
    _CFLAGS="${_CFLAGS} -DUSE_MANUAL=1"

    options="${options} -DCURL_CA_PATH=none"
    options="${options} -DCURL_CA_BUNDLE=none"
    if [ "${pass}" = 'shared' ]; then
      options="${options} -DBUILD_SHARED_LIBS=ON"
      options="${options} -DBUILD_CURL_EXE=OFF"
    else
      options="${options} -DBUILD_SHARED_LIBS=OFF"
      options="${options} -DBUILD_CURL_EXE=ON"
    fi
    options="${options} -DENABLE_THREADED_RESOLVER=ON"
    options="${options} -DBUILD_TESTING=OFF"

    if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
      _LDFLAGS_EXE="${_LDFLAGS_EXE} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-exe.tar"
      _LDFLAGS_DLL="${_LDFLAGS_DLL} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dll.tar"
    fi

    # shellcheck disable=SC2086
    cmake . -B "${_BLDDIR}-${pass}" ${_CMAKE_GLOBAL} ${options} \
      "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"  \
      "-DCMAKE_EXE_LINKER_FLAGS=${_LDFLAGS} ${_LDFLAGS_EXE}" \
      "-DCMAKE_SHARED_LINKER_FLAGS=${_LDFLAGS} ${_LDFLAGS_DLL}"  # --debug-find

    make --directory="${_BLDDIR}-${pass}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}" VERBOSE=1

    # Manual copy to DESTDIR

    if [ "${pass}" = 'shared' ]; then
      cp -p "${_BLDDIR}-${pass}/lib/${_DEF_NAME}" "${_pkg}"/bin/
    fi

    if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
      if [ "${pass}" = 'shared' ]; then
        cp -p "${_BLDDIR}-${pass}/lib/${_MAP_NAME}" "${_pkg}"/bin/
      else
        cp -p "${_BLDDIR}-${pass}/src/${_MAP_NAME}" "${_pkg}"/bin/
      fi
    fi
  done

  # Download CA bundle
  # CAVEAT: Build-time download. It can break reproducibility.
  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
    [ -f '../ca-bundle.crt' ] || \
      curl --disable --user-agent '' --fail --silent --show-error \
        --remote-time --xattr \
        --output '../ca-bundle.crt' \
        'https://curl.se/ca/cacert.pem'

    openssl dgst -sha256 '../ca-bundle.crt'
    openssl dgst -sha512 '../ca-bundle.crt'
  fi

  # Make steps for determinism

  readonly _ref='CHANGES'

  # binutils 2.38 has issues handling lld output:
  # - failing on implibs or creating corrupted output (depending on options).
  # - not stripping the .buildid section, which contains a timestamp.
  # LLVM's own llvm-objcopy does not seems to work with Windows binaries,
  # so .exe and .dll stripping is done via the -s linker option.
  if [ "${_LD}" = 'ld' ]; then
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-all   "${_pkg}"/bin/*.exe
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-all   "${_pkg}"/bin/*.dll
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.dll.a
  fi
  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.a

  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.exe
  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.dll

  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.exe
  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.dll

  touch -c -r "${_ref}" "${_pkg}"/bin/*.exe
  touch -c -r "${_ref}" "${_pkg}"/bin/*.dll
  touch -c -r "${_ref}" "${_pkg}"/bin/*.def
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" "${_pkg}"/bin/*.map
  fi

  # Tests

  "${_OBJDUMP}" --all-headers "${_pkg}"/bin/*.exe | grep -a -E -i "(file format|dll name)"
  "${_OBJDUMP}" --all-headers "${_pkg}"/bin/*.dll | grep -a -E -i "(file format|dll name)"

  # Execute curl and compiled-in dependency code. This is not secure, but
  # the build process already requires executing external code
  # (e.g. configure scripts) on the build machine, so this does not make
  # it worse, except that it requires installing WINE on a compatible CPU
  # (and a QEMU setup on non-compatible ones). It would be best to extract
  # `--version` output directly from the binary as strings, but curl creates
  # most of these strings dynamically at runtime, so this is not possible
  # (as of curl 7.83.1).
  ${_WINE} "${_pkg}"/bin/curl.exe --version | tee "curl-${_CPU}.txt"

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
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    for file in docs/libcurl/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -F '.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p "${_pkg}"/include/curl/*.h "${_DST}/include/curl/"
  cp -f -p "${_pkg}"/bin/*.exe        "${_DST}/bin/"
  cp -f -p "${_pkg}"/bin/*.dll        "${_DST}/bin/"
  cp -f -p "${_pkg}"/bin/*.def        "${_DST}/bin/"
  cp -f -p "${_pkg}"/lib/*.a          "${_DST}/lib/"
  cp -f -p docs/*.md                  "${_DST}/docs/"
  cp -f -p CHANGES                    "${_DST}/CHANGES.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README                     "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES              "${_DST}/RELEASE-NOTES.txt"

  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
    cp -f -p scripts/mk-ca-bundle.pl "${_DST}/"
    cp -f -p ../ca-bundle.crt        "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p "${_pkg}"/bin/*.map      "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
