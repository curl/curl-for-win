#!/bin/sh -ex

# WORK-IN-SLOW-PROGRESS

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.' | cut -f 1 -d '_')"
_VER="$1"

(
  cd "${_NAM}" || exit

  # Cross-tasks

  if [ "${_OS}" = 'win' ]; then
    opt_gmsys='-GMSYS Makefiles'
    # Without this option, the value '/usr/local' becomes 'msys64/usr/local'
    export MSYS2_ARG_CONV_EXCL='-DCMAKE_INSTALL_PREFIX='
  fi

  # Prepare build

  find . -name '*.dll' -delete
  find . -name '*.def' -delete

  # Build

  rm -r -f pkg

  find . -name '*.a'  -delete
  find . -name '*.pc' -delete

  for pass in 'static'; do

    rm -r -f CMakeFiles CMakeCache.txt cmake_install.cmake

    find . -name '*.o'   -delete
    find . -name '*.obj' -delete
    find . -name '*.lo'  -delete
    find . -name '*.la'  -delete
    find . -name '*.lai' -delete
    find . -name '*.Plo' -delete

    # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # public libcurl functions being marked as 'exported'. It is useful to
    # avoid the chance of libcurl functions getting exported from final
    # binaries when linked against static libcurl lib.
    _CFLAGS="${_OPTM} -fno-ident -DCURL_STATICLIB"
    [ "${_CPU}" = 'x86' ] && _CFLAGS="${_CFLAGS} -fno-asynchronous-unwind-tables"
    _LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
    if [ "${_CPU}" = 'x86' ]; then
      _LDFLAGS_EXE='-Wl,--pic-executable,-e,_mainCRTStartup'
    else
      _LDFLAGS_EXE='-Wl,--pic-executable,-e,mainCRTStartup'
      _LDFLAGS="${_LDFLAGS} -Wl,--high-entropy-va"
      _LDFLAGS_DLL='-Wl,--image-base,0x150000000'
    fi
    if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
      _LDFLAGS_EXE="${_LDFLAGS_EXE} -Wl,-Map,curl.map"
      _LDFLAGS_DLL="${_LDFLAGS_DLL} -Wl,-Map,libcurl.map"
    fi

    options='-DCMAKE_SYSTEM_NAME=Windows'
    options="${options} -DCMAKE_BUILD_TYPE=Release"
    # A bizarre fix that became required around year 2021 to not fail instantly
    # on macOS when using clang. Likely not the correct/complete fix.
    [ "${_OS}" = 'mac' ] && options="${options} -DCMAKE_AR=${_SYSROOT}/bin/${_CCPREFIX}ar"
    [ "${pass}" = 'static' ] && options="${options} -DBUILD_SHARED_LIBS=0"
    [ "${pass}" = 'shared' ] && options="${options} -DBUILD_SHARED_LIBS=1"
    options="${options} -DCURL_STATIC_CRT=1"
    options="${options} -DCURL_WINDOWS_SSPI=1"
    options="${options} -DCMAKE_USE_OPENSSL=1"
    options="${options} -DZLIB_INCLUDE_DIR:PATH=$(pwd)/../zlib/pkg/usr/local/include"
    options="${options} -DZLIB_LIBRARY:FILEPATH=$(pwd)/../zlib/pkg/usr/local/lib/libz.a"
    # For OpenSSL 3.x
    options="${options} -DOPENSSL_ROOT_DIR=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/"
    options="${options} -DOPENSSL_INCLUDE_DIR=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/include"
    options="${options} -DOPENSSL_LIBRARIES=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/lib"
    options="${options} -DOPENSSL_CRYPTO_LIBRARY=$(pwd)/../openssl/pkg/C:/Windows/System32/OpenSSL/lib"
    options="${options} -DCMAKE_RC_COMPILER=${_CCPREFIX}windres"
    options="${options} -DCMAKE_INSTALL_MESSAGE=NEVER"
    options="${options} -DCMAKE_INSTALL_PREFIX=/usr/local"

    if [ -d ../brotli ]; then
      options="${options} -DCURL_BROTLI=1"
      options="${options} -DBROTLI_INCLUDE_DIR:PATH=$(pwd)/../brotli/pkg/usr/local/include"
      options="${options} -DBROTLICOMMON_LIBRARY:FILEPATH=$(pwd)/../brotli/pkg/usr/local/lib/libbrotlicommon-static.a"
      options="${options} -DBROTLIDEV_LIBRARY:FILEPATH=$(pwd)/../brotli/pkg/usr/local/lib/libbrotlidec-static.a"
    fi
    if [ -d ../c-ares ]; then
      options="${options} -DENABLE_ARES=1"
    fi
    if [ -d ../libssh2 ]; then
      options="${options} -DLIBSSH2_INCLUDE_DIR:PATH=$(pwd)/../libssh2/pkg/usr/local/include"
      options="${options} -DLIBSSH2_LIBRARY:FILEPATH=$(pwd)/../libssh2/pkg/usr/local/lib/libssh2.a"
    fi
    if [ -d ../nghttp2 ]; then
      options="${options} -DUSE_NGHTTP2=1"
      options="${options} -DNGHTTP2_INCLUDE_DIR:PATH=$(pwd)/../nghttp2/pkg/usr/local/include"
      options="${options} -DNGHTTP2_LIBRARY:FILEPATH=$(pwd)/../nghttp2/pkg/usr/local/lib/libnghttp2.a"
      _CFLAGS="${_CFLAGS} -DNGHTTP2_STATICLIB"
    fi

    # https://cmake.org/cmake/help/v3.11/manual/cmake-properties.7.html#properties-on-targets
    [ "${pass}" = 'shared' ] && [ "${_CPU}" = 'x64' ] && options="${options} -DCMAKE_RELEASE_POSTFIX=-x64"

    if [ "${CC}" = 'mingw-clang' ]; then
      unset CC

      [ "${_OS}" = 'linux' ] && _CFLAGS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${_CFLAGS}"

      # '-DMINGW=1' required to detect OpenSSL

      # shellcheck disable=SC2086
      cmake . ${options} "${opt_gmsys}" \
        "-DMINGW=1" \
        "-DCMAKE_SYSROOT=${_SYSROOT}" \
        "-DCMAKE_LIBRARY_ARCHITECTURE=${_TRIPLET}" \
        "-DCMAKE_C_COMPILER_TARGET=${_TRIPLET}" \
        "-DCMAKE_C_COMPILER=clang" \
        "-DCMAKE_C_FLAGS=${_CFLAGS}" \
        "-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc ${_LDFLAGS_EXE}" \
        "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc ${_LDFLAGS_DLL}"
    else
      unset CC

      # shellcheck disable=SC2086
      cmake . ${options} "${opt_gmsys}" \
        "-DCMAKE_C_COMPILER=${_CCPREFIX}gcc" \
        "-DCMAKE_C_FLAGS=-static-libgcc ${_CFLAGS}" \
        "-DCMAKE_EXE_LINKER_FLAGS=${_LDFLAGS_EXE}" \
        "-DCMAKE_SHARED_LINKER_FLAGS=${_LDFLAGS_DLL}"
    fi

    make install "DESTDIR=$(pwd)/pkg"  # VERBOSE=1
  done

  # DESTDIR= + CMAKE_INSTALL_PREFIX
  _pkg='pkg/usr/local'

  if false; then
  options='mingw32-ipv6-sspi-ldaps-srp'

  # Generate .def file for libcurl by parsing curl headers.
  # Useful to limit .dll exports to libcurl functions meant to be exported.
  # Without this, the default linker logic kicks in, whereas every public
  # function is exported if none is marked for export explicitly. This
  # leads to exporting every libcurl public function, as well as any other
  # ones from statically linked dependencies, resulting in a larger .dll,
  # an inflated implib and a non-standard list of exported functions.
  echo 'EXPORTS' > libcurl.def
  {
    # CURL_EXTERN CURLcode curl_easy_send(CURL *curl, const void *buffer,
    grep -a -h '^CURL_EXTERN ' include/curl/*.h | grep -a -h -F '(' \
      | sed 's/CURL_EXTERN \([a-zA-Z_\* ]*\)[\* ]\([a-z_]*\)(\(.*\)$/\2/g'
    # curl_easy_option_by_name(const char *name);
    grep -a -h -E '^ *\*? *[a-z_]+ *\(.+\);$' include/curl/*.h \
      | sed -E 's|^ *\*? *([a-z_]+) *\(.+$|\1|g'
  } | grep -a -v '^$' | sort | tee -a libcurl.def
  CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} ../libcurl.def"

  if [ -d ../zlib-ng ]; then
    export ZLIB_PATH=../../zlib-ng/pkg/usr/local
  else
    export ZLIB_PATH=../../zlib/pkg/usr/local
  fi
  options="${options}-zlib"
  if [ -d ../brotli ]; then
    options="${options}-brotli"
    export BROTLI_PATH=../../brotli/pkg/usr/local
    export BROTLI_LIBS='-Wl,-Bstatic -lbrotlidec-static -lbrotlicommon-static -Wl,-Bdynamic'
  fi
  if [ -d ../zstd ]; then
    options="${options}-zstd"
    export ZSTD_PATH=../../zstd/build/cmake/pkg/usr/local
    export ZSTD_LIBS='-Wl,-Bstatic -lzstd -Wl,-Bdynamic'
  fi

  [ -d ../openssl ] && export OPENSSL_PATH=../../openssl
  if [ -n "${OPENSSL_PATH}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG"
    # Apply a workaround for deprecation warnings from the curl autoconf logic
    if [ "$(echo "${OPENSSL_VER_}" | cut -c -2)" = '3.' ]; then
      CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DOPENSSL_SUPPRESS_DEPRECATED"
    fi
    options="${options}-ssl"
    export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
    export OPENSSL_LIBPATH="${OPENSSL_PATH}"
    export OPENSSL_LIBS='-lssl -lcrypto'
  fi
  options="${options}-winssl"
  if [ -d ../libssh2 ]; then
    options="${options}-ssh2"
    export LIBSSH2_PATH=../../libssh2
  fi
  if [ -d ../nghttp2 ]; then
    options="${options}-nghttp2"
    export NGHTTP2_PATH=../../nghttp2/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP2_STATICLIB"
  fi
  if [ -d ../nghttp3 ]; then
    options="${options}-nghttp3-ngtcp2"
    export NGHTTP3_PATH=../../nghttp3/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP3_STATICLIB"
    export NGTCP2_PATH=../../ngtcp2/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGTCP2_STATICLIB"
  fi
  if [ -d ../c-ares ]; then
    options="${options}-ares"
    export LIBCARES_PATH=../../c-ares/pkg/usr/local
  fi
  if [ -d ../libgsasl ]; then
    options="${options}-gsasl"
    export LIBGSASL_PATH=../../libgsasl/pkg/usr/local
  fi
  if [ -d ../libidn2 ]; then
    options="${options}-idn2"
    export LIBIDN2_PATH=../../libidn2/pkg/usr/local
  else
    options="${options}-winidn"
  fi

  if [ "${_CPU}" = 'x64' ]; then
    export CURL_DLL_SUFFIX=-x64
  fi
  export CURL_DLL_A_SUFFIX=.dll

  # Make sure to link zlib (and only zlib) in static mode when building
  # `libcurl.dll`, so that it wouldn't depend on a `zlib1.dll`.
  # In some build environments (such as MSYS2), `libz.dll.a` is also offered
  # along with `libz.a` causing the linker to pick up the shared library.
  export DLL_LIBS='-Wl,-Bstatic -lz -Wl,-Bdynamic'

  # Link further libs to libcurl DLL in static mode by
  # deleting their implibs:
  rm -f \
    '../libssh2/win32/libssh2.dll.a' \
    '../libidn2/pkg/usr/local/lib/libidn2.dll.a' \
    '../libgsasl/pkg/usr/local/lib/libgsasl.dll.a' \
    '../openssl/libcrypto.dll.a' \
    '../openssl/libssl.dll.a'
  fi

  # Download CA bundle
  [ -f '../ca-bundle.crt' ] || \
    curl --disable --user-agent curl --fail --silent --show-error \
      --remote-time --xattr \
      --output '../ca-bundle.crt' \
      'https://curl.se/ca/cacert.pem'

  openssl dgst -sha256 '../ca-bundle.crt'
  openssl dgst -sha512 '../ca-bundle.crt'

  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives lib/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all src/*.exe
  "${_CCPREFIX}strip" --preserve-dates --strip-all lib/*.dll

  ../_peclean.py "${_ref}" src/*.exe
  ../_peclean.py "${_ref}" lib/*.dll

  ../_sign-code.sh "${_ref}" src/*.exe
  ../_sign-code.sh "${_ref}" lib/*.dll

  touch -c -r "${_ref}" src/*.exe
  touch -c -r "${_ref}" lib/*.dll
  touch -c -r "${_ref}" lib/*.def
  touch -c -r "${_ref}" lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" src/*.map
    touch -c -r "${_ref}" lib/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers src/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers lib/*.dll | grep -a -E -i "(file format|dll name)"

  ${_WINE} src/curl.exe --version
  ${_WINE} src/curl.exe --dump-module-paths

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
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
  cp -f -p docs/*.md                "${_DST}/docs/"
  cp -f -p include/curl/*.h         "${_DST}/include/curl/"
  cp -f -p src/*.exe                "${_DST}/bin/"
  cp -f -p lib/*.dll                "${_DST}/bin/"
  cp -f -p lib/*.def                "${_DST}/bin/"
  cp -f -p lib/*.a                  "${_DST}/lib/"
  cp -f -p lib/mk-ca-bundle.pl      "${_DST}/"
  cp -f -p CHANGES                  "${_DST}/CHANGES.txt"
  cp -f -p COPYING                  "${_DST}/COPYING.txt"
  cp -f -p README                   "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES            "${_DST}/RELEASE-NOTES.txt"
  cp -f -p ../ca-bundle.crt         "${_DST}/bin/curl-ca-bundle.crt"

  [ -d ../zlib-ng ]  && cp -f -p ../zlib-ng/LICENSE.md "${_DST}/COPYING-zlib-ng.md"
  [ -d ../zlib ]     && cp -f -p ../zlib/README        "${_DST}/COPYING-zlib.txt"
  [ -d ../zstd ]     && cp -f -p ../zstd/LICENSE       "${_DST}/COPYING-zstd.txt"
  [ -d ../brotli ]   && cp -f -p ../brotli/LICENSE     "${_DST}/COPYING-brotli.txt"
  [ -d ../libssh2 ]  && cp -f -p ../libssh2/COPYING    "${_DST}/COPYING-libssh2.txt"
  [ -d ../nghttp2 ]  && cp -f -p ../nghttp2/COPYING    "${_DST}/COPYING-nghttp2.txt"
  [ -d ../nghttp3 ]  && cp -f -p ../nghttp3/COPYING    "${_DST}/COPYING-nghttp3.txt"
  [ -d ../ngtcp2 ]   && cp -f -p ../ngtcp2/COPYING     "${_DST}/COPYING-ngtcp2.txt"
  [ -d ../libidn2 ]  && cp -f -p ../libidn2/COPYING    "${_DST}/COPYING-libidn2.txt"
  [ -d ../cares ]    && cp -f -p ../c-ares/LICENSE.md  "${_DST}/COPYING-c-ares.md"
  # OpenSSL 3.x
  [ -d ../openssl ] && [ -f ../openssl/LICENSE.txt ] && cp -f -p ../openssl/LICENSE.txt "${_DST}/COPYING-openssl.txt"
  # OpenSSL 1.x
  [ -d ../openssl ] && [ -f ../openssl/LICENSE     ] && cp -f -p ../openssl/LICENSE     "${_DST}/COPYING-openssl.txt"

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p src/*.map                "${_DST}/bin/"
    cp -f -p lib/*.map                "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
