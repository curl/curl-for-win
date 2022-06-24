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

  # Cross-tasks

  if [ "${_OS}" = 'win' ]; then
    opt_gmsys='-GMSYS Makefiles'
    # Without this option, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  else
    opt_gmsys=''
  fi

  # Build

  rm -r -f pkg CMakeFiles CMakeCache.txt CTestTestfile.cmake cmake_install.cmake

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.lo'  -delete
  find . -name '*.la'  -delete
  find . -name '*.lai' -delete
  find . -name '*.Plo' -delete
  find . -name '*.pc'  -delete
  find . -name '*.dll' -delete
  find . -name '*.def' -delete
  find . -name '*.map' -delete

  # Build

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

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

  if [ "${_CRT}" = 'ucrt' ] && [ "${_CC}" = 'clang' ]; then
    uselld=1
  else
    uselld=0
  fi

  # CMake cannot build everything in one pass. With BUILD_SHARED_LIBS enabled,
  # it does not build a static lib, and links curl.exe against libcurl DLL
  # with no option to change this. We need to split it into two passes. This
  # is be slower than when using a single pass (like in Makefile.m32), but
  # there is no other way. The two passes are:
  #   1. build the shared libcurl DLL + implib + .def
  #   2. build the static libcurl lib + statically linked curl EXE
  for pass in shared static; do

    options=''
    options="${options} -DCMAKE_SYSTEM_NAME=Windows"
    options="${options} -DCMAKE_BUILD_TYPE=Release"
    options="${options} -DCMAKE_DISABLE_PRECOMPILE_HEADERS=OFF"
    [ "${_OS}" = 'mac' ] && options="${options} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
    options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
    options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
    options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

    export _CFLAGS='-fno-ident -DHAVE_STRCASECMP -DHAVE_ATOMIC -DHAVE_SOCKADDR_IN6_SIN6_SCOPE_ID -DHAVE_STRTOK_R -DUSE_HEADERS_API'
    [ "${_CPU}" = 'x86' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"
    [ "${_CPU}" = 'x86' ] && options="${options} -DENABLE_INET_PTON=OFF"  # For Windows XP compatibility
    export CURL_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
    export CURL_LDFLAG_EXTRAS_EXE
    export CURL_LDFLAG_EXTRAS_DLL
    if [ "${_CPU}" = 'x86' ]; then
      CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,_mainCRTStartup'
      CURL_LDFLAG_EXTRAS_DLL=''
    else
      CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,mainCRTStartup'
      CURL_LDFLAG_EXTRAS_DLL='-Wl,--image-base,0x150000000'
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--high-entropy-va"
    fi

    if [ "${_CRT}" = 'ucrt' ]; then
      if [ "${_CC}" = 'clang' ]; then
        CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -fuse-ld=lld -s"
      else
        CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -specs=${_GCCSPECS}"
      fi
      _CFLAGS="${_CFLAGS} -D_UCRT"
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -lucrt"
    fi

    options="${options} -DCURL_OS_SUFFIX=-${_CPU}"

    # Disabled till we flesh out UNICODE support and document it enough to be
    # safe to use.
  # options="${options} -DENABLE_UNICODE=ON"

    CURL_DLL_SUFFIX=''
    [ "${_CPU}" = 'x64' ] && CURL_DLL_SUFFIX="-${_CPU}"
    [ "${_CPU}" = 'a64' ] && CURL_DLL_SUFFIX="-${_CPU}"

    [ "${pass}" = 'shared' ] && options="${options} -DCMAKE_SHARED_LIBRARY_SUFFIX_C=${CURL_DLL_SUFFIX}.dll"  # CMAKE_SHARED_LIBRARY_SUFFIX ignored.

    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,--output-def,libcurl${CURL_DLL_SUFFIX}.def"

    if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
      CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,-Map,curl.map"
      CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,-Map,libcurl${CURL_DLL_SUFFIX}.map"
    fi

    # Ugly hack. Everything breaks without this due to the accidental ordering of
    # libs and objects, and offering no universal way to (re)insert libs at
    # specific positions. Linker complains about a missing --end-group, then adds
    # it automatically anyway. Same with '-fuse-ld=lld'.
    CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--start-group"

    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} $(pwd)/libcurl.def"

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
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -lwldap32"
    fi

    if [ -d ../zlib ]; then
      options="${options} -DUSE_ZLIB=ON"
      options="${options} -DZLIB_LIBRARY=$(pwd)/../zlib/pkg/usr/local/lib/libz.a"
      options="${options} -DZLIB_INCLUDE_DIR=$(pwd)/../zlib/pkg/usr/local/include"
    else
      options="${options} -DUSE_ZLIB=OFF"
    fi
    if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
      options="${options} -DCURL_BROTLI=ON"
      options="${options} -DBROTLIDEC_LIBRARY=$(pwd)/../brotli/pkg/usr/local/lib/libbrotlidec.a"
      options="${options} -DBROTLICOMMON_LIBRARY=$(pwd)/../brotli/pkg/usr/local/lib/libbrotlicommon.a"
    else
      options="${options} -DCURL_BROTLI=OFF"
    fi

    if [ -d ../libressl ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=$(pwd)/../libressl/pkg/usr/local"
      options="${options} -DOPENSSL_INCLUDE_DIR=$(pwd)/../libressl/pkg/usr/local/include"
    elif [ -d ../openssl-quic ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=$(pwd)/../openssl-quic/pkg/usr/local"
      options="${options} -DOPENSSL_INCLUDE_DIR=$(pwd)/../openssl-quic/pkg/usr/local/include"
    elif [ -d ../openssl ]; then
      options="${options} -DCURL_USE_OPENSSL=ON"
      options="${options} -DOPENSSL_ROOT_DIR=$(pwd)/../openssl/pkg/usr/local"
      options="${options} -DOPENSSL_INCLUDE_DIR=$(pwd)/../openssl/pkg/usr/local/include"
    else
      options="${options} -DCURL_USE_OPENSSL=OFF"
    fi
    if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
      options="${options} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON"
      _CFLAGS="${_CFLAGS} -DHAVE_OPENSSL_SRP -DUSE_TLS_SRP"
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -lbcrypt"
    fi

    options="${options} -DCURL_USE_SCHANNEL=ON"
    _CFLAGS="${_CFLAGS} -DHAS_ALPN"

    if [ -d ../libssh2 ]; then
      options="${options} -DCURL_USE_LIBSSH2=ON"
      options="${options} -DLIBSSH2_LIBRARY=$(pwd)/../libssh2/pkg/usr/local/lib/libssh2.a"
      options="${options} -DLIBSSH2_INCLUDE_DIR=$(pwd)/../libssh2/pkg/usr/local/include"
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -lbcrypt"
    else
      options="${options} -DCURL_USE_LIBSSH2=OFF"  # Avoid detecting a copy on the host OS
    fi

    if [ -d ../nghttp2 ]; then
      options="${options} -DUSE_NGHTTP2=ON"
      options="${options} -DNGHTTP2_LIBRARY=$(pwd)/../nghttp2/pkg/usr/local/lib/libnghttp2.a"
      options="${options} -DNGHTTP2_INCLUDE_DIR=$(pwd)/../nghttp2/pkg/usr/local/include"
      _CFLAGS="${_CFLAGS} -DNGHTTP2_STATICLIB"
    else
      options="${options} -DUSE_NGHTTP2=OFF"
    fi
    if [ -d ../nghttp3 ] && [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
      options="${options} -DUSE_NGHTTP3=ON"
      options="${options} -DNGHTTP3_LIBRARY=$(pwd)/../nghttp3/pkg/usr/local/lib/libnghttp3.a"
      options="${options} -DNGHTTP3_INCLUDE_DIR=$(pwd)/../nghttp3/pkg/usr/local/include"
      _CFLAGS="${_CFLAGS} -DNGHTTP3_STATICLIB"

      options="${options} -DUSE_NGTCP2=ON"
      options="${options} -DNGTCP2_LIBRARY=$(pwd)/../ngtcp2/pkg/usr/local/lib/libngtcp2.a"
      options="${options} -DNGTCP2_INCLUDE_DIR=$(pwd)/../ngtcp2/pkg/usr/local/include"
      options="${options} -DCMAKE_LIBRARY_PATH=$(pwd)/../ngtcp2/pkg/usr/local/lib"
      _CFLAGS="${_CFLAGS} -DNGTCP2_STATICLIB"
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -lws2_32"  # Necessary for 'CheckQuicSupportInOpenSSL'
    else
      options="${options} -DUSE_NGHTTP3=OFF"
      options="${options} -DUSE_NGTCP2=OFF"
    fi
    if [ -d ../libgsasl ]; then
      _CFLAGS="${_CFLAGS} -DUSE_GSASL -I$(pwd)/../libgsasl/pkg/usr/local/include"
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -L$(pwd)/../libgsasl/pkg/usr/local/lib -lgsasl"
    fi
    if [ -d ../libidn2 ]; then  # Also for Windows XP compatibility
      options="${options} -DUSE_LIBIDN2=ON"
      _CFLAGS="${_CFLAGS} -I$(pwd)/../libidn2/pkg/usr/local/include"
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -L$(pwd)/../libidn2/pkg/usr/local/lib -lidn2"
    elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} -DUSE_LIBIDN2=OFF"
      options="${options} -DUSE_WIN32_IDN=ON"
    fi

    options="${options} -DENABLE_MANUAL=ON"  # Does not seem to work.
    _CFLAGS="${_CFLAGS} -DUSE_MANUAL=1"

    options="${options} -DCURL_CA_PATH=none"
    options="${options} -DCURL_CA_BUNDLE=none"
    if [ "${pass}" = 'static' ]; then
      # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
      # marking public libcurl functions as 'exported'. Useful to avoid the
      # chance of libcurl functions getting exported from final binaries when
      # linked against the static libcurl lib.
      _CFLAGS="${_CFLAGS} -DCURL_STATICLIB"
      options="${options} -DBUILD_SHARED_LIBS=OFF"
      options="${options} -DBUILD_CURL_EXE=ON"
    else
      options="${options} -DBUILD_SHARED_LIBS=ON"
      options="${options} -DBUILD_CURL_EXE=OFF"
    fi
    options="${options} -DENABLE_THREADED_RESOLVER=ON"
    options="${options} -DBUILD_TESTING=OFF"

    if [ "${_CC}" = 'clang' ]; then
      unset CC

      [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

    # _CFLAGS="${_CFLAGS} -Xclang -cfguard"

      # shellcheck disable=SC2086
      cmake . ${options} ${opt_gmsys} \
        "-DCMAKE_SYSROOT=${_SYSROOT}" \
        "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
        "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
        "-DCMAKE_C_COMPILER=clang${CW_CCSUFFIX}" \
        "-DCMAKE_C_FLAGS=${_CFLAGS}" \
        "-DCMAKE_EXE_LINKER_FLAGS=${CURL_LDFLAG_EXTRAS} ${CURL_LDFLAG_EXTRAS_EXE}" \
        "-DCMAKE_SHARED_LINKER_FLAGS=${CURL_LDFLAG_EXTRAS} ${CURL_LDFLAG_EXTRAS_DLL}"  # --debug-find
    else
      unset CC

      # shellcheck disable=SC2086
      cmake . ${options} ${opt_gmsys} \
        "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
        "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}" \
        "-DCMAKE_EXE_LINKER_FLAGS=${CURL_LDFLAG_EXTRAS} ${CURL_LDFLAG_EXTRAS_EXE}" \
        "-DCMAKE_SHARED_LINKER_FLAGS=${CURL_LDFLAG_EXTRAS} ${CURL_LDFLAG_EXTRAS_DLL}"
    fi

    make --jobs 2 install "DESTDIR=$(pwd)/pkg"  # VERBOSE=1
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
  if [ "${uselld}" = '0' ]; then
    "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-all   ${_pkg}/bin/*.exe
    "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-all   ${_pkg}/bin/*.dll
    "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/libcurl.dll.a
  fi
  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/libcurl.a

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.exe
  ../_peclean.py "${_ref}" ${_pkg}/bin/*.dll

  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.exe
  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.dll

  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/bin/*.dll
  touch -c -r "${_ref}" ./lib/*.def
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" ./src/*.map
    touch -c -r "${_ref}" ./lib/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.dll | grep -a -E -i "(file format|dll name)"

  # Execute curl and compiled-in dependency code. This is not secure, but
  # the build process already requires executing external code
  # (e.g. configure scripts) on the build machine, so this does not make
  # it worse, except that it requires installing WINE on a compatible CPU
  # (and a QEMU setup on non-compatible ones). It would be best to extract
  # `--version` output directly from the binary as strings, but curl creates
  # most of these strings dynamically at runtime, so this is not possible
  # (as of curl 7.83.1).
  ${_WINE} ${_pkg}/bin/curl.exe --version | tee "curl-${_CPU}.txt"

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
  cp -f -p ${_pkg}/include/curl/*.h "${_DST}/include/curl/"
  cp -f -p ${_pkg}/bin/*.exe        "${_DST}/bin/"
  cp -f -p ${_pkg}/bin/*.dll        "${_DST}/bin/"
  cp -f -p ./lib/*.def              "${_DST}/bin/"
  cp -f -p ${_pkg}/lib/*.a          "${_DST}/lib/"
  cp -f -p docs/*.md                "${_DST}/docs/"
  cp -f -p CHANGES                  "${_DST}/CHANGES.txt"
  cp -f -p COPYING                  "${_DST}/COPYING.txt"
  cp -f -p README                   "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES            "${_DST}/RELEASE-NOTES.txt"

  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
    cp -f -p scripts/mk-ca-bundle.pl "${_DST}/"
    cp -f -p ../ca-bundle.crt        "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p ./src/*.map              "${_DST}/bin/"
    cp -f -p ./lib/*.map              "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
