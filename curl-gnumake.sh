#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-gnumake//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  # Always delete targets, including ones made for a different CPU.
  find src -name '*.exe' -delete
  find src -name '*.map' -delete
  find lib -name '*.dll' -delete
  find lib -name '*.def' -delete
  find lib -name '*.map' -delete

  rm -r -f "${_PKGDIR}"

  # Build

  export CFG='-ipv6-sspi-srp'

  if [ "${CURL_VER_}" != '7.87.0' ]; then
    export ARCH='custom'  # TODO: Pending https://github.com/curl/curl/pull/9764
  fi

  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} -DNDEBUG -DOS=\\\"${_TRIPLET}\\\""
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL} -Wl,--nxcompat -Wl,--dynamicbase"
  export LIBS="${_LIBS_GLOBAL}"

  LDFLAGS_BIN=''
  LDFLAGS_LIB=''

  # Link lib dependencies in static mode. Implied by `-static` for curl,
  # but required for libcurl, which would link to shared libs by default.
  LIBS="${LIBS} -Wl,-Bstatic"

  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents marking
  # public libcurl functions as 'exported'. Useful to avoid the chance of
  # libcurl functions getting exported from final binaries when linked against
  # the static libcurl lib.
  CPPFLAGS="${CPPFLAGS} -DCURL_STATICLIB"

  # CPPFLAGS added after this point only affect libcurl.

  if [ "${_CPU}" = 'x86' ]; then
    LDFLAGS_BIN="${LDFLAGS_BIN} -Wl,--pic-executable,-e,_mainCRTStartup"
  else
    LDFLAGS_BIN="${LDFLAGS_BIN} -Wl,--pic-executable,-e,mainCRTStartup"
    LDFLAGS_LIB="${LDFLAGS_LIB} -Wl,--image-base,0x150000000"
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
    CFG="${CFG}-ldaps"
  fi

  if [ ! "${_BRANCH#*unicode*}" = "${_BRANCH}" ]; then
    CFG="${CFG}-unicode"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    LDFLAGS_BIN="${LDFLAGS_BIN} -Wl,-Map,curl.map"
    # shellcheck disable=SC2153
    LDFLAGS_LIB="${LDFLAGS_LIB} -Wl,-Map,libcurl${_CURL_DLL_SUFFIX}.map"
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
  LDFLAGS_LIB="${LDFLAGS_LIB} ../libcurl.def"

  if [ -n "${_ZLIB}" ]; then
    CFG="${CFG}-zlib"
    # Makefile.m32 expects the headers and lib in ZLIB_PATH, so adjust them
    # manually:
    export ZLIB_PATH="../../${_ZLIB}/${_PP}/include"
    LDFLAGS="${LDFLAGS} -L../../${_ZLIB}/${_PP}/lib"
  fi
  if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
    CFG="${CFG}-brotli"
    export BROTLI_PATH="../../brotli/${_PP}"
  fi
  if [ -d ../zstd ] && [ "${_BRANCH#*nozstd*}" = "${_BRANCH}" ]; then
    CFG="${CFG}-zstd"
    export ZSTD_PATH="../../zstd/${_PP}"
  fi

  h3=0

  if [ -n "${_OPENSSL}" ]; then
    CFG="${CFG}-ssl"
    export OPENSSL_PATH="../../${_OPENSSL}/${_PP}"

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
        #    clang-15: error: linker command failed with exit code 1 (use -v to see invocation)
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
        LIBS="${LIBS} -Wl,-Bdynamic -lpthread -Wl,-Bstatic"
      else
        LIBS="${LIBS} -lpthread"
      fi
      h3=1
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      h3=1
    elif [ "${_OPENSSL}" = 'openssl-quic' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      # Workaround for 3.x deprecation warnings
      CPPFLAGS="${CPPFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
      [ "${_OPENSSL}" = 'openssl-quic' ] && h3=1
    fi
  fi

  if [ -d ../wolfssl ]; then
    CFG="${CFG}-wolfssl"
    export WOLFSSL_PATH="../../wolfssl/${_PP}"
    h3=1
  fi
  if [ -d ../mbedtls ]; then
    CFG="${CFG}-mbedtls"
    export MBEDTLS_PATH="../../mbedtls/${_PP}"
  fi

  CFG="${CFG}-schannel"
  CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

  if [ -d ../wolfssh ] && [ -d ../wolfssl ]; then
    CFG="${CFG}-wolfssh"
    export WOLFSSH_PATH="../../wolfssh/${_PP}"
  elif [ -d ../libssh ]; then
    CFG="${CFG}-libssh"
    export LIBSSH_PATH="../../libssh/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DLIBSSH_STATIC"
  elif [ -d ../libssh2 ]; then
    CFG="${CFG}-ssh2"
    export LIBSSH2_PATH="../../libssh2/${_PP}"
  fi
  if [ -d ../nghttp2 ]; then
    CFG="${CFG}-nghttp2"
    export NGHTTP2_PATH="../../nghttp2/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DNGHTTP2_STATICLIB"
  fi

  [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ] || h3=0

  if [ "${h3}" = '1' ] && [ -d ../nghttp3 ] && [ -d ../ngtcp2 ]; then
    CFG="${CFG}-nghttp3-ngtcp2"
    export NGHTTP3_PATH="../../nghttp3/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DNGHTTP3_STATICLIB"
    export NGTCP2_PATH="../../ngtcp2/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB"
  fi
  if [ -d ../cares ]; then
    CFG="${CFG}-ares"
    export LIBCARES_PATH="../../cares/${_PP}"
    CPPFLAGS="${CPPFLAGS} -DCARES_STATICLIB"
  fi
  if [ -d ../gsasl ]; then
    CFG="${CFG}-gsasl"
    export LIBGSASL_PATH="../../gsasl/${_PP}"
  fi
  if [ -d ../libidn2 ]; then
    CFG="${CFG}-idn2"
    export LIBIDN2_PATH="../../libidn2/${_PP}"

    if [ -d ../libpsl ]; then
      CFG="${CFG}-psl"
      export LIBPSL_PATH="../../libpsl/${_PP}"
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
    CFG="${CFG}-winidn"
  fi

  [ "${_BRANCH#*noftp*}" != "${_BRANCH}" ] && CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_FTP=1"

  CPPFLAGS="${CPPFLAGS} -DUSE_WEBSOCKETS"

  if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
    LDFLAGS_LIB="${LDFLAGS_LIB} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dll.tar"
    LDFLAGS_BIN="${LDFLAGS_BIN} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-exe.tar"
  fi

  [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && export AR="${AR_NORMALIZE}"

  export CURL_LDFLAGS_LIB="${LDFLAGS_LIB}"
  export CURL_LDFLAGS_BIN="${LDFLAGS_BIN}"

  export CURL_DLL_SUFFIX="${_CURL_DLL_SUFFIX}"

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    if [ "${CW_MAP}" = '1' ]; then
      find src -name '*.map' -delete
      find lib -name '*.map' -delete
    fi
    "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.m32 distclean
    "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.m32 distclean
  fi

  "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.m32
  "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.m32

  # Install manually

  mkdir -p "${_PP}/include/curl"
  mkdir -p "${_PP}/lib"
  mkdir -p "${_PP}/bin"

  cp -f -p ./include/curl/*.h "${_PP}/include/curl/"
  cp -f -p ./src/*.exe        "${_PP}/bin/"
  cp -f -p ./lib/*.dll        "${_PP}/bin/"
  cp -f -p ./lib/*.def        "${_PP}/bin/"
  cp -f -p ./lib/*.a          "${_PP}/lib/"

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p ./src/*.map "${_PP}/bin/"
    cp -f -p ./lib/*.map "${_PP}/bin/"
  fi

  . ../curl-pkg.sh
)
