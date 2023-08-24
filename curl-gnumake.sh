#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Unixy platforms require the configure phase, thus cannot build with pure GNU Make.
if [ "${_OS}" != 'win' ]; then
  ./curl-cmake.sh "$@"
  exit
fi

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

  rm -r -f "${_PKGDIR:?}"

  # Build

  export CFG='-ipv6'

  export CC="${_CC_GLOBAL}"
  export CFLAGS="${_CFLAGS_GLOBAL} -O3 ${_CFLAGS_GLOBAL_WPICKY}"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} -DOS=\\\"${_TRIPLET}\\\""
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

  LDFLAGS_BIN="${_LDFLAGS_BIN_GLOBAL}"
  LDFLAGS_LIB=''

  if [ "${_OS}" = 'win' ]; then
    CFG="${CFG}-sspi"
  fi

  if [ ! "${_BRANCH#*werror*}" = "${_BRANCH}" ]; then
    CFLAGS="${CFLAGS} -Werror"
  fi

  if [ ! "${_BRANCH#*debug*}" = "${_BRANCH}" ]; then
    CFG="${CFG}-debug-trackmem"
  fi

  # Link lib dependencies in static mode. Implied by `-static` for curl,
  # but required for libcurl, which would link to shared libs by default.
  LIBS="${LIBS} -Wl,-Bstatic"

  if [ "${CURL_VER_}" = '8.3.0' ]; then
    # Use -DCURL_STATICLIB when compiling libcurl. This option prevents marking
    # public libcurl functions as 'exported'. Useful to avoid the chance of
    # libcurl functions getting exported from final binaries when linked against
    # the static libcurl lib.
    CPPFLAGS="${CPPFLAGS} -DCURL_STATICLIB"
  fi

  # CPPFLAGS added after this point only affect libcurl.

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
  fi

  if [ "${_OS}" = 'win' ] && [ "${_BRANCH#*unicode*}" != "${_BRANCH}" ]; then
    CFG="${CFG}-unicode"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    CFG="${CFG}-map"
  fi

  if [ -n "${_ZLIB}" ]; then
    CFG="${CFG}-zlib"
    export ZLIB_PATH="../../${_ZLIB}/${_PP}"
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
      CPPFLAGS="${CPPFLAGS} -DHAVE_SSL_SET0_WBIO"
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        # Non-production workaround for:
        # mingw-w64 x64 winpthread static lib incompatible with UCRT.
        # ```c
        # /*
        #    llvm/clang
        #    $ /usr/local/opt/llvm/bin/clang -fuse-ld=lld \
        #        -target x86_64-w64-mingw32 --sysroot /usr/local/opt/mingw-w64/toolchain-x86_64 \
        #        test.c -D_UCRT -Wl,-Bstatic -lpthread -Wl,-Bdynamic -lucrt
        #
        #    gcc
        #    $ x86_64-w64-mingw32-gcc -dumpspecs | sed 's/-lmsvcrt/-lucrt/g' > gcc-specs-ucrt
        #    $ x86_64-w64-mingw32-gcc -specs=gcc-specs-ucrt \
        #        test.c -D_UCRT -Wl,-Bstatic -lpthread -Wl,-Bdynamic -lucrt
        #
        #    ``` llvm/clang ->
        #    ld.lld: error: undefined symbol: _setjmp
        #    >>> referenced by ../src/thread.c:1518
        #    >>>               libpthread.a(libwinpthread_la-thread.o):(pthread_create_wrapper)
        #    clang-16: error: linker command failed with exit code 1 (use -v to see invocation)
        #    ```
        #    ``` gcc ->
        #    /usr/local/Cellar/mingw-w64/11.0.1/toolchain-x86_64/bin/x86_64-w64-mingw32-ld: /usr/local/Cellar/mingw-w64/11.0.1/toolchain-x86_64/lib/gcc/x86_64-w64-mingw32/13.2.0/../../../../x86_64-w64-mingw32/lib/../lib/libpthread.a(libwinpthread_la-thread.o): in function `pthread_create_wrapper':
        #    /private/tmp/mingw-w64-20230808-5242-1g3t1oo/mingw-w64-v11.0.1/mingw-w64-libraries/winpthreads/build-x86_64/../src/thread.c:1518:(.text+0xb78): undefined reference to `_setjmp'
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
    elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      CPPFLAGS="${CPPFLAGS} -DHAVE_SSL_SET0_WBIO"
      [ "${_OPENSSL}" = 'quictls' ] && h3=1
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

  if [ "${_OS}" = 'win' ]; then
    CFG="${CFG}-schannel"
  fi
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
  elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && [ "${_OS}" = 'win' ]; then
    CFG="${CFG}-winidn"
  fi

  [ "${_BRANCH#*noftp*}" != "${_BRANCH}" ] && CPPFLAGS="${CPPFLAGS} -DCURL_DISABLE_FTP=1"

  CPPFLAGS="${CPPFLAGS} -DUSE_WEBSOCKETS"

  if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
    LDFLAGS_LIB="${LDFLAGS_LIB} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dyn.tar"
    LDFLAGS_BIN="${LDFLAGS_BIN} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-bin.tar"
  fi

  [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && export AR="${AR_NORMALIZE}"

  export CURL_LDFLAGS_LIB="${LDFLAGS_LIB}"
  export CURL_LDFLAGS_BIN="${LDFLAGS_BIN}"

  # shellcheck disable=SC2153
  export CURL_DLL_SUFFIX="${_CURL_DLL_SUFFIX}"

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.mk distclean
    "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.mk distclean
  fi

  "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.mk
  "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.mk

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
