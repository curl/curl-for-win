#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# CMake build takes 25% longer than Makefile.m32, as of 2022-07-04.

# https://cmake.org/cmake/help/latest/manual/cmake-properties.7.html
# https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  rm -r -f "${_PKGDIR}" "${_BLDDIR}-shared" "${_BLDDIR}-static"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # Build

  # Generate .def file for libcurl by parsing curl headers. Useful to export
  # the libcurl functions meant to be exported.
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
      | sed -E 's/^ *\*? *([a-z_]+) *\(.+$/\1/g'
  } | grep -a -v '^$' | sort | tee -a libcurl.def

  # CMake cannot build everything in one pass. With BUILD_SHARED_LIBS enabled,
  # it does not build a static lib, and links curl.exe against libcurl DLL
  # with no option to change this. We need to split it into two passes:
  #   1. build shared libcurl DLL + implib + .def
  #   2. build static libcurl lib + statically linked curl EXE
  for pass in shared static; do

    CFLAGS='-W -Wall'
    CPPFLAGS=''

    CPPFLAGS="${CPPFLAGS} -DHAVE_STRCASECMP -DHAVE_STRTOK_R -DHAVE_FTRUNCATE -DHAVE_GETADDRINFO_THREADSAFE"
    CPPFLAGS="${CPPFLAGS} -DHAVE_SIGNAL -DHAVE_SOCKADDR_IN6_SIN6_SCOPE_ID"
    CPPFLAGS="${CPPFLAGS} -DHAVE_UNISTD_H"
    CPPFLAGS="${CPPFLAGS} -DUSE_HEADERS_API"

    options=''

    [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && options="${options} -DCMAKE_AR=${AR_NORMALIZE}"

    LIBS=''
    LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
    LDFLAGS_EXE=''
    LDFLAGS_DLL=''
    if [ "${_CPU}" = 'x86' ]; then
      CPPFLAGS="${CPPFLAGS} -D_WIN32_WINNT=0x0501 -DHAVE_ATOMIC"  # For Windows XP compatibility
      LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,--pic-executable,-e,_mainCRTStartup"
    else
      CPPFLAGS="${CPPFLAGS} -DHAVE_INET_NTOP -DHAVE_STRUCT_POLLFD"
      LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,--pic-executable,-e,mainCRTStartup"
      LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,--image-base,0x150000000"
      LDFLAGS="${LDFLAGS} -Wl,--high-entropy-va"
    fi

    if [ ! "${_BRANCH#*unicode*}" = "${_BRANCH}" ]; then
      options="${options} -DENABLE_UNICODE=ON"
    fi

    if [ "${pass}" = 'shared' ]; then
      options="${options} -DCMAKE_SHARED_LIBRARY_SUFFIX_C=${_CURL_DLL_SUFFIX}.dll"
      _DEF_NAME="libcurl${_CURL_DLL_SUFFIX}.def"
      LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,--output-def,${_DEF_NAME}"
    fi

    if [ "${CW_MAP}" = '1' ]; then
      if [ "${pass}" = 'shared' ]; then
        _MAP_NAME="libcurl${_CURL_DLL_SUFFIX}.map"
        LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,-Map,${_MAP_NAME}"
      else
        _MAP_NAME='curl.map'
        LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,-Map,${_MAP_NAME}"
      fi
    fi

    # Ugly hack. Everything breaks without this due to the accidental ordering of
    # libs and objects, and offering no universal way to (re)insert libs at
    # specific positions. Linker complains about a missing --end-group, then adds
    # it automatically anyway.
    if [ "${_LD}" = 'ld' ]; then
      LDFLAGS="${LDFLAGS} -Wl,--start-group"
    fi

    LDFLAGS_DLL="${LDFLAGS_DLL} $(pwd)/libcurl.def"

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
      [ "${_BRANCH#*noftp*}" != "${_BRANCH}" ] && CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_FTP=1"

      CPPFLAGS="${CPPFLAGS} -DHAVE_LDAP_SSL"
      LIBS="${LIBS} -lwldap32"
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
    if [ -d ../zstd ]; then
      options="${options} -DCURL_ZSTD=ON"
      options="${options} -DZstd_LIBRARY=${_TOP}/zstd/${_PP}/lib/libzstd.a"
      options="${options} -DZstd_INCLUDE_DIR=${_TOP}/zstd/${_PP}/include"
    else
      options="${options} -DCURL_ZSTD=OFF"
    fi

    if [ -d ../libressl ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/libressl/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/libressl/${_PP}/include"
      CPPFLAGS="${CPPFLAGS} -DHAVE_OPENSSL_SRP -DUSE_TLS_SRP"
      LIBS="${LIBS} -lbcrypt"
    elif [ -d ../boringssl ]; then
      CPPFLAGS="${CPPFLAGS} -DCURL_BORINGSSL_VERSION=\\\"$(printf '%.8s' "${BORINGSSL_VER_}")\\\""
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/boringssl/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/boringssl/${_PP}/include"
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ]; then  # FIXME
        LIBS="${LIBS} -Wl,-Bdynamic -lpthread -Wl,-Bstatic"
      else
        LIBS="${LIBS} -Wl,-Bstatic -lpthread -Wl,-Bdynamic"
      fi
    elif [ -d ../openssl-quic ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/openssl-quic/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/openssl-quic/${_PP}/include"
      CPPFLAGS="${CPPFLAGS} -DHAVE_OPENSSL_SRP -DUSE_TLS_SRP"
      LIBS="${LIBS} -lbcrypt"
    elif [ -d ../openssl ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=${_TOP}/openssl/${_PP}"
      options="${options} -DOPENSSL_INCLUDE_DIR=${_TOP}/openssl/${_PP}/include"
      CPPFLAGS="${CPPFLAGS} -DHAVE_OPENSSL_SRP -DUSE_TLS_SRP"
      LIBS="${LIBS} -lbcrypt"
    else
      options="${options} -DCURL_USE_OPENSSL=OFF"
    fi
    if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ] || [ -d ../boringssl ]; then
      options="${options} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON"
    fi

    options="${options} -DCURL_USE_SCHANNEL=ON"
    CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

    if [ -d ../libssh2 ]; then
      options="${options} -DCURL_USE_LIBSSH2=ON"
      options="${options} -DLIBSSH2_LIBRARY=${_TOP}/libssh2/${_PP}/lib/libssh2.a"
      options="${options} -DLIBSSH2_INCLUDE_DIR=${_TOP}/libssh2/${_PP}/include"
      LIBS="${LIBS} -lbcrypt"

      if [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ]; then
        # By passing -lssh2 _before_ -lcrypto (of openssl/libressl) to the linker,
        # DLL size becomes closer/identical to autotools/m32-built DLLs. Otherwise
        # this is not necessary, and there should not be any functional difference.
        # Could not find the reason for it. File-offset-stripped-then-sorted .map
        # files are identical either way. It would be useful to have a linker
        # option to sort object/lib inputs to make output deterministic (these
        # build do not rely on any ordering side-effects.)
        LDFLAGS="${LDFLAGS} -L${_TOP}/libssh2/${_PP}/lib"
        LIBS="${LIBS} -lssh2"
      fi
    else
      options="${options} -DCURL_USE_LIBSSH2=OFF"
    fi

    if [ -d ../nghttp2 ]; then
      options="${options} -DUSE_NGHTTP2=ON"
      options="${options} -DNGHTTP2_LIBRARY=${_TOP}/nghttp2/${_PP}/lib/libnghttp2.a"
      options="${options} -DNGHTTP2_INCLUDE_DIR=${_TOP}/nghttp2/${_PP}/include"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP2_STATICLIB"
    else
      options="${options} -DUSE_NGHTTP2=OFF"
    fi
    if [ -d ../nghttp3 ] && [ -d ../ngtcp2 ] && [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
      options="${options} -DUSE_NGHTTP3=ON"
      options="${options} -DNGHTTP3_LIBRARY=${_TOP}/nghttp3/${_PP}/lib/libnghttp3.a"
      options="${options} -DNGHTTP3_INCLUDE_DIR=${_TOP}/nghttp3/${_PP}/include"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP3_STATICLIB"

      options="${options} -DUSE_NGTCP2=ON"
      options="${options} -DNGTCP2_LIBRARY=${_TOP}/ngtcp2/${_PP}/lib/libngtcp2.a"
      options="${options} -DNGTCP2_INCLUDE_DIR=${_TOP}/ngtcp2/${_PP}/include"
      options="${options} -DCMAKE_LIBRARY_PATH=${_TOP}/ngtcp2/${_PP}/lib"
      CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB"
      LIBS="${LIBS} -lws2_32"  # Necessary for 'CheckQuicSupportInOpenSSL'
    else
      options="${options} -DUSE_NGHTTP3=OFF"
      options="${options} -DUSE_NGTCP2=OFF"
    fi
    if [ -d ../libgsasl ]; then
      CPPFLAGS="${CPPFLAGS} -DUSE_GSASL"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/libgsasl/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/libgsasl/${_PP}/lib"
      LIBS="${LIBS} -lgsasl"
    fi
    if [ -d ../libidn2 ]; then
      options="${options} -DUSE_LIBIDN2=ON"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/libidn2/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/libidn2/${_PP}/lib"
      LIBS="${LIBS} -lidn2"

      if [ -d ../libpsl ] && [ -d ../libiconv ] && [ -d ../libunistring ]; then
        options="${options} -DUSE_LIBPSL=ON"
        options="${options} -DLIBPSL_LIBRARY=${_TOP}/libpsl/${_PP}/lib/libpsl.a;${_TOP}/libiconv/${_PP}/lib/libiconv.a;${_TOP}/libunistring/${_PP}/lib/libunistring.a"
        options="${options} -DLIBPSL_INCLUDE_DIR=${_TOP}/libpsl/${_PP}/include"
      fi

      if [ -d ../libiconv ]; then
        LDFLAGS="${LDFLAGS} -L${_TOP}/libiconv/${_PP}/lib"
        LIBS="${LIBS} -liconv"
      fi
      if [ -d ../libunistring ]; then
        LDFLAGS="${LDFLAGS} -L${_TOP}/libunistring/${_PP}/lib"
        LIBS="${LIBS} -lunistring"
      fi
    elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} -DUSE_LIBIDN2=OFF"
      options="${options} -DUSE_WIN32_IDN=ON"
    fi

    options="${options} -DENABLE_MANUAL=ON"  # Does not seem to work.
    CPPFLAGS="${CPPFLAGS} -DUSE_MANUAL=1"

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
      LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-exe.tar"
      LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dll.tar"
    fi

    # shellcheck disable=SC2086
    cmake . -B "${_BLDDIR}-${pass}" ${_CMAKE_GLOBAL} ${options} \
      "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}"  \
      "-DCMAKE_EXE_LINKER_FLAGS=${LDFLAGS} ${LDFLAGS_EXE} ${LIBS}" \
      "-DCMAKE_SHARED_LINKER_FLAGS=${LDFLAGS} ${LDFLAGS_DLL} ${LIBS}"  # --debug-find --debug-trycompile

    if [ "${pass}" = 'static' ] && \
       [ -f src/tool_hugehelp.c ]; then  # File missing when building from a raw source tree.
      # When doing an out of tree build, this is necessary to avoid make
      # re-generating the embedded manual with blank content.
      cp -p src/tool_hugehelp.c "${_BLDDIR}-${pass}/src/"
    fi

    make --directory="${_BLDDIR}-${pass}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" VERBOSE=1

    # Manual copy to DESTDIR

    if [ "${pass}" = 'shared' ]; then
      cp -p "${_BLDDIR}-${pass}/lib/${_DEF_NAME}" "${_pkg}"/bin/
    fi

    if [ "${CW_MAP}" = '1' ]; then
      if [ "${pass}" = 'shared' ]; then
        cp -p "${_BLDDIR}-${pass}/lib/${_MAP_NAME}" "${_pkg}"/bin/
      else
        cp -p "${_BLDDIR}-${pass}/src/${_MAP_NAME}" "${_pkg}"/bin/
      fi
    fi
  done

  # Download CA bundle
  # CAVEAT: Build-time download. It can break reproducibility.
  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ] || [ -d ../boringssl ]; then
    [ -f '../ca-bundle.crt' ] || \
      curl --disable --user-agent '' --fail --silent --show-error \
        --remote-time --xattr \
        --output '../ca-bundle.crt' \
        'https://curl.se/ca/cacert.pem'

    openssl dgst -sha256 '../ca-bundle.crt'
  fi

  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_pkg}"/bin/*.exe
  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_pkg}"/bin/*.dll
  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.a
  # LLVM strip does not support implibs, but they are deterministic by default:
  #   error: unsupported object file format
  [ "${_LD}" = 'ld' ] && "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.dll.a

  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.exe
  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.dll

  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.exe
  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.dll

  touch -c -r "${_ref}" "${_pkg}"/bin/*.exe
  touch -c -r "${_ref}" "${_pkg}"/bin/*.dll
  touch -c -r "${_ref}" "${_pkg}"/bin/*.def
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  if [ "${CW_MAP}" = '1' ]; then
    touch -c -r "${_ref}" "${_pkg}"/bin/*.map
  fi

  # Tests

  # Show the reference timestamp in UTC.
  case "${_OS}" in
    bsd|mac) TZ=UTC stat -f '%N: %Sm' -t '%Y-%m-%d %H:%M' "${_ref}";;
    *)       TZ=UTC stat --format '%n: %y' "${_ref}";;
  esac

  TZ=UTC "${_OBJDUMP}" --all-headers "${_pkg}"/bin/*.exe | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f
  TZ=UTC "${_OBJDUMP}" --all-headers "${_pkg}"/bin/*.dll | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f

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

  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ] || [ -d ../boringssl ]; then
    cp -f -p scripts/mk-ca-bundle.pl "${_DST}/"
    cp -f -p ../ca-bundle.crt        "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_pkg}"/bin/*.map      "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
