#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-m32//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  # Prepare build

  find . -name '*.dll' -delete
  find . -name '*.def' -delete
  find . -name '*.map' -delete

  # Build

  options='mingw32-ipv6-sspi-srp'

  export ARCH
  if [ "${_CPU}" = 'x64' ]; then
    ARCH='w64'
  elif [ "${_CPU}" = 'x86' ]; then
    ARCH='w32'
  else
    ARCH='custom'
  fi

  CFLAGS=''
  CPPFLAGS="-DOS=\\\"${_TRIPLET}\\\""

  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # marking public libcurl functions as 'exported'. Useful to avoid the
  # chance of libcurl functions getting exported from final binaries when
  # linked against the static libcurl lib.
  CPPFLAGS="${CPPFLAGS} -DCURL_STATICLIB -DNDEBUG"
  CPPFLAGS="${CPPFLAGS} -DHAVE_STRTOK_R -DHAVE_FTRUNCATE -D_FILE_OFFSET_BITS=64"
  CPPFLAGS="${CPPFLAGS} -DHAVE_INET_PTON -DHAVE_INET_NTOP"
  CPPFLAGS="${CPPFLAGS} -DHAVE_LIBGEN_H -DHAVE_BASENAME"
  CPPFLAGS="${CPPFLAGS} -DHAVE_SIGNAL -DHAVE_BOOL_T -DSIZEOF_OFF_T=8"
  CPPFLAGS="${CPPFLAGS} -DHAVE_STDBOOL_H -DHAVE_STRING_H -DHAVE_SETJMP_H"
  CPPFLAGS="${CPPFLAGS} -DUSE_HEADERS_API"

  LIBS=''
  LDFLAGS='-Wl,--nxcompat -Wl,--dynamicbase'
  LDFLAGS_EXE=''
  LDFLAGS_DLL=''
  if [ "${_CPU}" = 'x86' ]; then
    LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,--pic-executable,-e,_mainCRTStartup"
  else
    LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,--pic-executable,-e,mainCRTStartup"
    LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,--image-base,0x150000000"
    LDFLAGS="${LDFLAGS} -Wl,--high-entropy-va"
  fi

  if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ] || \
     [ ! "${_BRANCH#*nano*}" = "${_BRANCH}" ]; then
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_ALTSVC=1"
  fi

  if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_CRYPTO_AUTH=1"
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_DICT=1 -DCURL_DISABLE_FILE=1 -DCURL_DISABLE_GOPHER=1 -DCURL_DISABLE_MQTT=1 -DCURL_DISABLE_RTSP=1 -DCURL_DISABLE_SMB=1 -DCURL_DISABLE_TELNET=1 -DCURL_DISABLE_TFTP=1"
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_FTP=1"
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_IMAP=1 -DCURL_DISABLE_POP3=1 -DCURL_DISABLE_SMTP=1"
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_LDAP=1 -DCURL_DISABLE_LDAPS=1"
  else
    options="${options}-ldaps"
  fi

  if [ ! "${_BRANCH#*unicode*}" = "${_BRANCH}" ]; then
    CPPFLAGS="${CPPFLAGS} -DUNICODE -D_UNICODE"
    LDFLAGS_EXE="${LDFLAGS_EXE} -municode"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,-Map,curl.map"
    # shellcheck disable=SC2153
    LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,-Map,libcurl${_CURL_DLL_SUFFIX}.map"
  fi

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
  LDFLAGS_DLL="${LDFLAGS_DLL} ../libcurl.def"

  # NOTE: Makefile.m32 automatically enables -zlib with -ssh2
  if [ -n "${_ZLIB}" ]; then
    options="${options}-zlib"
    export ZLIB_PATH="../../${_ZLIB}/${_PP}/include"
    # Makefile.m32 looks for the lib in ZLIB_PATH, so adjust it manually:
    LDFLAGS="${LDFLAGS} -L../../${_ZLIB}/${_PP}/lib"

    # Make sure to link zlib (and only zlib) in static mode when building
    # `libcurl.dll`, so that it would not depend on a `zlib1.dll`.
    # In some build environments (such as MSYS2), `libz.dll.a` is also offered
    # along with `libz.a` causing the linker to pick up the shared library.
    export DLL_LIBS='-Wl,-Bstatic -lz -Wl,-Bdynamic'
  fi
  if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
    options="${options}-brotli"
    export BROTLI_PATH="../../brotli/${_PP}"
    export BROTLI_LIBS='-Wl,-Bstatic -lbrotlidec -lbrotlicommon -Wl,-Bdynamic'
  fi
  if [ -d ../zstd ] && [ "${_BRANCH#*nozstd*}" = "${_BRANCH}" ]; then
    options="${options}-zstd"
    export ZSTD_PATH="../../zstd/${_PP}"
    export ZSTD_LIBS='-Wl,-Bstatic -lzstd -Wl,-Bdynamic'
  fi

  h3=0

  if [ -n "${_OPENSSL}" ]; then
    options="${options}-ssl"
    export OPENSSL_PATH="../../${_OPENSSL}/${_PP}"
    export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
    export OPENSSL_LIBPATH="${OPENSSL_PATH}/lib"
    export OPENSSL_LIBS='-lssl -lcrypto'
    CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG"

    if [ "${_OPENSSL}" = 'boringssl' ]; then
      CPPFLAGS="${CPPFLAGS} -DCURL_BORINGSSL_VERSION=\\\"$(printf '%.8s' "${BORINGSSL_VER_}")\\\""
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        # Non-production workaround for:
        # mingw-w64 x64 winpthread static lib incompatible with UCRT.
        # ```c
        # /*
        #    clang
        #    $ /usr/local/opt/llvm/bin/clang -fuse-ld=lld \
        #        -target x86_64-w64-mingw32 --sysroot /usr/local/opt/mingw-w64/toolchain-x86_64 \
        #        test.c -D_UCRT -Wl,-Bstatic -lpthread -Wl,-Bdynamic -lucrt
        #
        #    gcc
        #    $ x86_64-w64-mingw32-gcc -dumpspecs | sed 's/-lmsvcrt/-lucrt/g' > gcc-specs-ucrt
        #    $ x86_64-w64-mingw32-gcc -specs=gcc-specs-ucrt \
        #        test.c -D_UCRT -Wl,-Bstatic -lpthread -Wl,-Bdynamic -lucrt
        #
        #    ``` clang ->
        #    ld.lld: error: undefined symbol: _setjmp
        #    >>> referenced by ../src/thread.c:1518
        #    >>>               libpthread.a(libwinpthread_la-thread.o):(pthread_create_wrapper)
        #    clang-14: error: linker command failed with exit code 1 (use -v to see invocation)
        #    ```
        #    ``` gcc ->
        #    /usr/local/Cellar/mingw-w64/10.0.0_3/toolchain-x86_64/bin/x86_64-w64-mingw32-ld: /usr/local/Cellar/mingw-w64/10.0.0_3/toolchain-x86_64/lib/gcc/x86_64-w64-mingw32/12.2.0/../../../../x86_64-w64-mingw32/lib/../lib/libpthread.a(libwinpthread_la-thread.o): in function `pthread_create_wrapper':
        #    /private/tmp/mingw-w64-20220820-4738-rfttcn/mingw-w64-v10.0.0/mingw-w64-libraries/winpthreads/build-x86_64/../src/thread.c:1518: undefined reference to `_setjmp'
        #    collect2: error: ld returned 1 exit status
        #    ```
        #  */
        # #include <pthread.h>
        # int main(void) {
        #   pthread_rwlock_t lock;
        #   pthread_rwlock_init(&lock, NULL);
        #   return 0;
        # }
        # ```
        # Ref: https://github.com/niXman/mingw-builds/issues/498
        OPENSSL_LIBS="${OPENSSL_LIBS} -Wl,-Bdynamic -lpthread -Wl,-Bstatic"
      else
        OPENSSL_LIBS="${OPENSSL_LIBS} -Wl,-Bstatic -lpthread -Wl,-Bdynamic"
      fi
      h3=1
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      OPENSSL_LIBS="${OPENSSL_LIBS} -lbcrypt"
    elif [ "${_OPENSSL}" = 'openssl-quic' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      OPENSSL_LIBS="${OPENSSL_LIBS} -lbcrypt"
      # Workaround for 3.x deprecation warnings
      CPPFLAGS="${CPPFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
      [ "${_OPENSSL}" = 'openssl-quic' ] && h3=1
    fi
  fi

  multissl=0

  if [ -d ../wolfssl ]; then
    CPPFLAGS="${CPPFLAGS} -DUSE_WOLFSSL -DSIZEOF_LONG_LONG=8"
    CPPFLAGS="${CPPFLAGS} -I../../wolfssl/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L../../wolfssl/${_PP}/lib"
    LIBS="${LIBS} -lwolfssl"
    multissl=1
    h3=1
  fi

  if [ -d ../mbedtls ]; then
    CPPFLAGS="${CPPFLAGS} -DUSE_MBEDTLS"
    CPPFLAGS="${CPPFLAGS} -I../../mbedtls/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L../../mbedtls/${_PP}/lib"
    LIBS="${LIBS} -lmbedtls -lmbedx509 -lmbedcrypto"
    multissl=1
  fi

  [ "${multissl}" = '1' ] && CPPFLAGS="${CPPFLAGS} -DCURL_WITH_MULTI_SSL"  # Fixup for cases undetected by Makefile.m32

  options="${options}-schannel"
  CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

  if [ -d ../wolfssh ] && [ -d ../wolfssl ]; then
    CPPFLAGS="${CPPFLAGS} -DUSE_WOLFSSH"
    CPPFLAGS="${CPPFLAGS} -I../../wolfssh/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L../../wolfssh/${_PP}/lib"
    LIBS="${LIBS} -lwolfssh"
  elif [ -d ../libssh ]; then
    CPPFLAGS="${CPPFLAGS} -DUSE_LIBSSH -DHAVE_LIBSSH_LIBSSH_H"
    CPPFLAGS="${CPPFLAGS} -DLIBSSH_STATIC"
    CPPFLAGS="${CPPFLAGS} -I../../libssh/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L../../libssh/${_PP}/lib"
    LIBS="${LIBS} -lssh"
  elif [ -d ../libssh2 ]; then
    options="${options}-ssh2"
    export LIBSSH2_PATH="../../libssh2/${_PP}"
    LDFLAGS="${LDFLAGS} -L${LIBSSH2_PATH}/lib"
  fi
  if [ -d ../nghttp2 ]; then
    options="${options}-nghttp2"
    export NGHTTP2_PATH="../../nghttp2/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DNGHTTP2_STATICLIB"
  fi

  [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ] || h3=0

  if [ "${h3}" = '1' ] && [ -d ../nghttp3 ] && [ -d ../ngtcp2 ]; then
    options="${options}-nghttp3-ngtcp2"
    export NGHTTP3_PATH="../../nghttp3/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DNGHTTP3_STATICLIB"
    export NGTCP2_PATH="../../ngtcp2/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB"
    export NGTCP2_LIBS='-lngtcp2'
    if [ "${_OPENSSL}" = 'boringssl' ]; then
      NGTCP2_LIBS="${NGTCP2_LIBS} -lngtcp2_crypto_boringssl"
    elif [ "${_OPENSSL}" = 'openssl-quic' ]; then
      NGTCP2_LIBS="${NGTCP2_LIBS} -lngtcp2_crypto_openssl"
    elif [ -d ../wolfssl ]; then
      NGTCP2_LIBS="${NGTCP2_LIBS} -lngtcp2_crypto_wolfssl"
    fi
  fi
  if [ -d ../cares ]; then
    options="${options}-ares"
    export LIBCARES_PATH="../../cares/${_PP}/lib"
    CPPFLAGS="${CPPFLAGS} -I../../cares/${_PP}/include"
    CPPFLAGS="${CPPFLAGS} -DCARES_STATICLIB"
  fi
  if [ -d ../libgsasl ]; then
    options="${options}-gsasl"
    export LIBGSASL_PATH="../../libgsasl/${_PP}"
  fi
  if [ -d ../libidn2 ]; then
    options="${options}-idn2"
    export LIBIDN2_PATH="../../libidn2/${_PP}"

    if [ -d ../libpsl ]; then
      CPPFLAGS="${CPPFLAGS} -DUSE_LIBPSL"
      CPPFLAGS="${CPPFLAGS} -I../../libpsl/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L../../libpsl/${_PP}/lib"
      LIBS="${LIBS} -lpsl"
    fi

    if [ -d ../libiconv ]; then
      LDFLAGS="${LDFLAGS} -L../../libiconv/${_PP}/lib"
      LIBS="${LIBS} -liconv"
    fi
    if [ -d ../libunistring ]; then
      LDFLAGS="${LDFLAGS} -L../../libunistring/${_PP}/lib"
      LIBS="${LIBS} -lunistring"
    fi
  elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
    options="${options}-winidn"
  fi

  [ "${_BRANCH#*noftp*}" != "${_BRANCH}" ] && CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_FTP=1"

  [ "${CURL_VER_}" != '7.85.0' ] && options="${options} -DUSE_WEBSOCKETS"

  if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
    LDFLAGS_DLL="${LDFLAGS_DLL} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dll.tar"
    LDFLAGS_EXE="${LDFLAGS_EXE} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-exe.tar"
  fi

  # Load above values into the variables Makefile.m32 expects
  export CURL_CC="${_CC_GLOBAL}"
  export CURL_STRIP="${_STRIP}"
  export CURL_RC="${RC}"
  export CURL_AR="${AR}"
  export CURL_RANLIB="${RANLIB}"

  [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && CURL_AR="${AR_NORMALIZE}"

  export CURL_RCFLAG_EXTRAS="${_RCFLAGS_GLOBAL}"
  export CURL_CFLAG_EXTRAS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${CPPFLAGS}"
  export CURL_LDFLAG_EXTRAS="${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${LDFLAGS} ${LIBS}"
  export CURL_LDFLAG_EXTRAS_DLL="${LDFLAGS_DLL}"
  export CURL_LDFLAG_EXTRAS_EXE="${LDFLAGS_EXE}"

  export CURL_DLL_SUFFIX="${_CURL_DLL_SUFFIX}"
  export CURL_DLL_A_SUFFIX='.dll'

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.m32 clean
    "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.m32 clean
  fi

  "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.m32 CFG="${options}"
  "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.m32 CFG="${options}"

  _pkg='.'

  # Download CA bundle
  # CAVEAT: Build-time download. It can break reproducibility.
  if [ -n "${_OPENSSL}" ]; then
    [ -f '../ca-bundle.crt' ] || \
      curl --disable --user-agent '' --fail --silent --show-error \
        --remote-time --xattr \
        --output '../ca-bundle.crt' \
        'https://curl.se/ca/cacert.pem'

    openssl dgst -sha256 '../ca-bundle.crt'
  fi

  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_pkg}"/src/*.exe
  "${_STRIP}" --enable-deterministic-archives --strip-all   "${_pkg}"/lib/*.dll
  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.a
  # LLVM strip does not support implibs, but they are deterministic by default:
  #   error: unsupported object file format
  [ "${_LD}" = 'ld' ] && "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.dll.a

  ../_peclean.py "${_ref}" "${_pkg}"/src/*.exe
  ../_peclean.py "${_ref}" "${_pkg}"/lib/*.dll

  ../_sign-code.sh "${_ref}" "${_pkg}"/src/*.exe
  ../_sign-code.sh "${_ref}" "${_pkg}"/lib/*.dll

  touch -c -r "${_ref}" "${_pkg}"/src/*.exe
  touch -c -r "${_ref}" "${_pkg}"/lib/*.dll
  touch -c -r "${_ref}" "${_pkg}"/lib/*.def
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  if [ "${CW_MAP}" = '1' ]; then
    touch -c -r "${_ref}" "${_pkg}"/src/*.map
    touch -c -r "${_ref}" "${_pkg}"/lib/*.map
  fi

  # Tests

  # Show the reference timestamp in UTC.
  case "${_OS}" in
    bsd|mac) TZ=UTC stat -f '%N: %Sm' -t '%Y-%m-%d %H:%M' "${_ref}";;
    *)       TZ=UTC stat --format '%n: %y' "${_ref}";;
  esac

  TZ=UTC "${_OBJDUMP}" --all-headers "${_pkg}"/src/*.exe | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f
  TZ=UTC "${_OBJDUMP}" --all-headers "${_pkg}"/lib/*.dll | grep -a -E -i "(file format|DLL Name|Time/Date)" | sort -r -f

  # Execute curl and compiled-in dependency code. This is not secure, but
  # the build process already requires executing external code
  # (e.g. configure scripts) on the build machine, so this does not make
  # it worse, except that it requires installing WINE on a compatible CPU
  # (and a QEMU setup on non-compatible ones). It would be best to extract
  # `--version` output directly from the binary as strings, but curl creates
  # most of these strings dynamically at runtime, so this is not possible
  # (as of curl 7.83.1).
  ${_WINE} "${_pkg}"/src/curl.exe --version | tee "curl-${_CPU}.txt"

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
  cp -f -p "${_pkg}"/src/*.exe        "${_DST}/bin/"
  cp -f -p "${_pkg}"/lib/*.dll        "${_DST}/bin/"
  cp -f -p "${_pkg}"/lib/*.def        "${_DST}/bin/"
  cp -f -p "${_pkg}"/lib/*.a          "${_DST}/lib/"
  cp -f -p docs/*.md                  "${_DST}/docs/"
  cp -f -p CHANGES                    "${_DST}/CHANGES.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README                     "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES              "${_DST}/RELEASE-NOTES.txt"

  if [ -n "${_OPENSSL}" ]; then
    cp -f -p scripts/mk-ca-bundle.pl  "${_DST}/"
    cp -f -p ../ca-bundle.crt         "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_pkg}"/src/*.map      "${_DST}/bin/"
    cp -f -p "${_pkg}"/lib/*.map      "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
