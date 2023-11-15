#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Unixy platforms require the configure phase, thus cannot build with pure GNU Make.
if [ "${_OS}" != 'win' ] || [ "${CURL_VER_}" != '8.4.0' ]; then
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
  export CFLAGS="${_CFLAGS_GLOBAL} -O3"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} -DOS=\\\"${_TRIPLET}\\\""
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS=''

  CFLAGS+=' -fvisibility=hidden'

  if [ "${CURL_VER_}" = '8.4.0' ]; then
    CPPFLAGS+=' -DHAVE_VARIADIC_MACROS_C99=1 -DHAVE_VARIADIC_MACROS_GCC=1'
    CPPFLAGS+=' -DHAVE_SNPRINTF=1'
  fi

  # Picky compiler warnings as seen in curl CMake/autotools.
  # builds with llvm/clang 15 and gcc 12.2:
  #   https://clang.llvm.org/docs/DiagnosticsReference.html
  #   https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
  CFLAGS+=' -pedantic -Wbad-function-cast -Wcast-align -Wconversion -Wdeclaration-after-statement -Wdouble-promotion -Wempty-body -Wendif-labels -Wenum-conversion -Wfloat-equal -Wignored-qualifiers -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wno-format-nonliteral -Wno-long-long -Wno-multichar -Wno-sign-conversion -Wno-system-headers -Wold-style-definition -Wpointer-arith -Wshadow -Wsign-compare -Wstrict-prototypes -Wtype-limits -Wundef -Wunused -Wunused-const-variable -Wvla -Wwrite-strings'
  [ "${_CC}" = 'llvm' ] && CFLAGS+=' -Wassign-enum -Wcomma -Wextra-semi-stmt -Wmissing-variable-declarations -Wshift-sign-overflow -Wshorten-64-to-32'
  [ "${_CC}" = 'gcc'  ] && CFLAGS+=' -Walloc-zero -Warith-conversion -Warray-bounds=2 -Wclobbered -Wduplicated-branches -Wduplicated-cond -Wformat-overflow=2 -Wformat-truncation=2 -Wformat=2 -Wmissing-parameter-type -Wno-pedantic-ms-format -Wnull-dereference -Wold-style-declaration -Wrestrict -Wshift-negative-value -Wshift-overflow=2 -Wstrict-aliasing=3 -fdelete-null-pointer-checks -ftree-vrp'

  [[ "${_CONFIG}" != *'main'* ]] && LDFLAGS+=' -v'

  LDFLAGS_BIN="${_LDFLAGS_BIN_GLOBAL}"
  LDFLAGS_LIB=''

  if [ "${_OS}" = 'win' ]; then
    CFG+='-sspi'
  fi

  if [[ "${_CONFIG}" = *'werror'* ]]; then
    CFLAGS+=' -Werror'
  fi

  if [[ "${_CONFIG}" = *'debug'* ]]; then
    CFG+='-debug-trackmem'
  fi

  # Link lib dependencies in static mode. Implied by `-static` for curl,
  # but required for libcurl, which would link to shared libs by default.
  LIBS+=' -Wl,-Bstatic'

  # CPPFLAGS added after this point only affect libcurl.

  # for H2/H3
  if [[ "${_CONFIG}" =~ (zero|bldtst|pico|nano) ]]; then
    CPPFLAGS+=' -DCURL_DISABLE_ALTSVC=1'
  fi

  if [[ "${_CONFIG}" =~ (zero|bldtst) ]] && \
     [[ "${_CONFIG}" = *'osnotls'* ]]; then
    CPPFLAGS+=' -DCURL_DISABLE_HSTS=1'
  fi

  if [[ "${_CONFIG}" =~ (zero|bldtst|pico) ]]; then
    CPPFLAGS+=' -DCURL_DISABLE_BASIC_AUTH=1 -DCURL_DISABLE_BEARER_AUTH=1 -DCURL_DISABLE_DIGEST_AUTH=1 -DCURL_DISABLE_KERBEROS_AUTH=1 -DCURL_DISABLE_NEGOTIATE_AUTH=1 -DCURL_DISABLE_AWS=1'
    CPPFLAGS+=' -DCURL_DISABLE_NTLM=1'
    CPPFLAGS+=' -DCURL_DISABLE_DICT=1 -DCURL_DISABLE_FILE=1 -DCURL_DISABLE_GOPHER=1 -DCURL_DISABLE_MQTT=1 -DCURL_DISABLE_RTSP=1 -DCURL_DISABLE_SMB=1 -DCURL_DISABLE_TELNET=1 -DCURL_DISABLE_TFTP=1'
    CPPFLAGS+=' -DCURL_DISABLE_FTP=1'
    CPPFLAGS+=' -DCURL_DISABLE_POP3=1 -DCURL_DISABLE_SMTP=1'
    [[ "${_CONFIG}" != *'imap'* ]] && CPPFLAGS+=' -DCURL_DISABLE_IMAP=1'
    CPPFLAGS+=' -DCURL_DISABLE_LDAP=1 -DCURL_DISABLE_LDAPS=1'
    # Not possible to disable USE_UNIX_SOCKETS with GNU Make
  else
    CPPFLAGS+=' -DUSE_WEBSOCKETS=1'
  fi

  if [ "${_OS}" = 'win' ] && [[ "${_CONFIG}" = *'unicode'* ]]; then
    CFG+='-unicode'
  fi

  if [ "${CW_MAP}" = '1' ]; then
    CFG+='-map'
  fi

  if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then
    CFG+='-zlib'
    export ZLIB_PATH="../../${_ZLIB}/${_PP}"
  fi
  if [[ "${_DEPS}" = *'brotli'* ]] && [ -d "../brotli/${_PP}" ]; then
    CFG+='-brotli'
    export BROTLI_PATH="../../brotli/${_PP}"
  fi
  if [[ "${_DEPS}" = *'zstd'* ]] && [ -d "../zstd/${_PP}" ]; then
    CFG+='-zstd'
    export ZSTD_PATH="../../zstd/${_PP}"
  fi

  h3=0

  if [ -n "${_OPENSSL}" ] && [ -d "../${_OPENSSL}/${_PP}" ]; then
    CFG+='-ssl'
    export OPENSSL_PATH="../../${_OPENSSL}/${_PP}"

    if [ "${_OPENSSL}" = 'boringssl' ] || [ "${_OPENSSL}" = 'awslc' ]; then
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        CPPFLAGS+=" -DCURL_BORINGSSL_VERSION=\\\"$(printf '%.8s' "${BORINGSSL_VER_}")\\\""
      fi
      CPPFLAGS+=' -DHAVE_SSL_SET0_WBIO'
      if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
        LIBS+=' -Wl,-Bdynamic -lpthread -Wl,-Bstatic'
      else
        LIBS+=' -lpthread'
      fi
      h3=1
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      [ "${_OS}" = 'win' ] && CPPFLAGS+=' -DLIBRESSL_DISABLE_OVERRIDE_WINCRYPT_DEFINES_WARNING'
      h3=1
    elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'openssl' ]; then
      CPPFLAGS+=' -DHAVE_SSL_SET0_WBIO'
      [ "${_OPENSSL}" = 'quictls' ] && h3=1
    fi
  fi

  if [[ "${_DEPS}" = *'wolfssl'* ]] && [ -d "../wolfssl/${_PP}" ]; then
    CFG+='-wolfssl'
    export WOLFSSL_PATH="../../wolfssl/${_PP}"
    h3=1
  fi
  if [[ "${_DEPS}" = *'mbedtls'* ]] && [ -d "../mbedtls/${_PP}" ]; then
    CFG+='-mbedtls'
    export MBEDTLS_PATH="../../mbedtls/${_PP}"
  fi

  if [[ "${_CONFIG}" != *'osnotls'* ]]; then
    if [ "${_OS}" = 'win' ]; then
      CFG+='-schannel'
    fi
  fi
  CPPFLAGS+=' -DHAS_ALPN'  # for mbedTLS, OpenSSL, Schannel when enabled

# CPPFLAGS+=' -DCURL_CA_FALLBACK=1'

  if [[ "${_DEPS}" = *'wolfssh'* ]] && [ -d "../wolfssh/${_PP}" ] && \
     [[ "${_DEPS}" = *'wolfssl'* ]] && [ -d "../wolfssl/${_PP}" ]; then
    CFG+='-wolfssh'
    export WOLFSSH_PATH="../../wolfssh/${_PP}"
  elif [[ "${_DEPS}" = *'libssh1'* ]] && [ -d "../libssh/${_PPS}" ]; then
    CFG+='-libssh'
    export LIBSSH_PATH="../../libssh/${_PPS}"
    CPPFLAGS+=' -DLIBSSH_STATIC'
  elif [[ "${_DEPS}" = *'libssh2'* ]] && [ -d "../libssh2/${_PPS}" ]; then
    CFG+='-ssh2'
    export LIBSSH2_PATH="../../libssh2/${_PPS}"
  fi
  if [[ "${_DEPS}" = *'nghttp2'* ]] && [ -d "../nghttp2/${_PP}" ]; then
    CFG+='-nghttp2'
    export NGHTTP2_PATH="../../nghttp2/${_PP}"
    CPPFLAGS+=' -DNGHTTP2_STATICLIB'
  fi

  if [ "${h3}" = '1' ] && \
     [[ "${_DEPS}" = *'nghttp3'* ]] && [ -d "../nghttp3/${_PP}" ] && \
     [[ "${_DEPS}" = *'ngtcp2'* ]] && [ -d "../ngtcp2/${_PPS}" ]; then
    CFG+='-nghttp3-ngtcp2'
    export NGHTTP3_PATH="../../nghttp3/${_PP}"
    CPPFLAGS+=' -DNGHTTP3_STATICLIB'
    export NGTCP2_PATH="../../ngtcp2/${_PPS}"
    CPPFLAGS+=' -DNGTCP2_STATICLIB'
  fi
  if [[ "${_DEPS}" = *'cares'* ]] && [ -d "../cares/${_PP}" ]; then
    CFG+='-ares'
    export LIBCARES_PATH="../../cares/${_PP}"
    CPPFLAGS+=' -DCARES_STATICLIB'
  fi
  if [[ "${_DEPS}" = *'gsasl'* ]] && [ -d "../gsasl/${_PPS}" ]; then
    CFG+='-gsasl'
    export LIBGSASL_PATH="../../gsasl/${_PPS}"
  fi
  if [[ "${_DEPS}" = *'libidn2'* ]] && [ -d "../libidn2/${_PP}" ]; then
    CFG+='-idn2'
    export LIBIDN2_PATH="../../libidn2/${_PP}"

    if [[ "${_DEPS}" = *'libpsl'* ]] && [ -d "../libpsl/${_PP}" ]; then
      CFG+='-psl'
      export LIBPSL_PATH="../../libpsl/${_PP}"
    fi

    if [[ "${_DEPS}" = *'libiconv'* ]] && [ -d "../libiconv/${_PP}" ]; then
      LDFLAGS+=" -L../../libiconv/${_PP}/lib"
      LIBS+=' -liconv'
    fi
    if [[ "${_DEPS}" = *'libunistring'* ]] && [ -d "../libunistring/${_PP}" ]; then
      LDFLAGS+=" -L../../libunistring/${_PP}/lib"
      LIBS+=' -lunistring'
    fi
  elif [[ ! "${_CONFIG}" =~ (pico|osnoidn) ]] && \
       [ "${_OS}" = 'win' ]; then
    CFG+='-winidn'
  fi

  [[ "${_CONFIG}" = *'noftp'* ]] && CPPFLAGS+=' -DCURL_DISABLE_FTP=1'

  if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
    LDFLAGS_LIB+=" -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dyn.tar"
    LDFLAGS_BIN+=" -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-bin.tar"
  fi

  [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && export AR="${AR_NORMALIZE}"

  export CURL_LDFLAGS_LIB="${LDFLAGS_LIB}"
  export CURL_LDFLAGS_BIN="${LDFLAGS_BIN}"

  # shellcheck disable=SC2153
  export CURL_DLL_SUFFIX="${_CURL_DLL_SUFFIX}"

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ]; then
    "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.mk distclean
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.mk distclean
    fi
  fi

  "${_MAKE}" --jobs="${_JOBS}" --directory=lib --makefile=Makefile.mk
  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    "${_MAKE}" --jobs="${_JOBS}" --directory=src --makefile=Makefile.mk
  fi

  # Install manually

  mkdir -p "${_PP}/include/curl"
  mkdir -p "${_PP}/lib"
  mkdir -p "${_PP}/bin"

  cp -f -p ./include/curl/*.h "${_PP}/include/curl/"
  cp -f -p ./lib/*.dll        "${_PP}/bin/"
  cp -f -p ./lib/*.def        "${_PP}/bin/"
  cp -f -p ./lib/*.a          "${_PP}/lib/"

  if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
    cp -f -p ./src/*.exe        "${_PP}/bin/"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    if [[ "${_CONFIG}" != *'nocurltool'* ]]; then
      cp -f -p ./src/*.map "${_PP}/bin/"
    fi
    cp -f -p ./lib/*.map "${_PP}/${DYN_DIR}/"
  fi

  . ../curl-pkg.sh
)
