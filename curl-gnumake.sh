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
  export CFLAGS="${_CFLAGS_GLOBAL} -O3 ${_CFLAGS_GLOBAL_WPICKY}"
  export CPPFLAGS="${_CPPFLAGS_GLOBAL} -DOS=\\\"${_TRIPLET}\\\""
  export RCFLAGS="${_RCFLAGS_GLOBAL}"
  export LDFLAGS="${_LDFLAGS_GLOBAL}"
  export LIBS="${_LIBS_GLOBAL}"

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

  if [[ "${_CONFIG}" = *'zero'* ]] || \
     [[ "${_CONFIG}" = *'bldtst'* ]] || \
     [[ "${_CONFIG}" = *'pico'* ]] || \
     [[ "${_CONFIG}" = *'nano'* ]]; then
    CPPFLAGS+=' -DCURL_DISABLE_ALTSVC=1'
  fi

  if [[ "${_CONFIG}" = *'zero'* ]] || \
     [[ "${_CONFIG}" = *'bldtst'* ]] || \
     [[ "${_CONFIG}" = *'pico'* ]]; then
    CPPFLAGS+=' -DCURL_DISABLE_CRYPTO_AUTH=1'
    CPPFLAGS+=' -DCURL_DISABLE_DICT=1 -DCURL_DISABLE_FILE=1 -DCURL_DISABLE_GOPHER=1 -DCURL_DISABLE_MQTT=1 -DCURL_DISABLE_RTSP=1 -DCURL_DISABLE_SMB=1 -DCURL_DISABLE_TELNET=1 -DCURL_DISABLE_TFTP=1'
    CPPFLAGS+=' -DCURL_DISABLE_FTP=1'
    CPPFLAGS+=' -DCURL_DISABLE_IMAP=1 -DCURL_DISABLE_POP3=1 -DCURL_DISABLE_SMTP=1'
    CPPFLAGS+=' -DCURL_DISABLE_LDAP=1 -DCURL_DISABLE_LDAPS=1'
  fi

  if [ "${_OS}" = 'win' ] && [[ "${_CONFIG}" = *'unicode'* ]]; then
    CFG+='-unicode'
  fi

  if [ "${CW_MAP}" = '1' ]; then
    CFG+='-map'
  fi

  if [ -n "${_ZLIB}" ]; then
    CFG+='-zlib'
    export ZLIB_PATH="../../${_ZLIB}/${_PP}"
  fi
  if [ -d ../brotli ] && [[ "${_CONFIG}" != *'nobrotli'* ]]; then
    CFG+='-brotli'
    export BROTLI_PATH="../../brotli/${_PP}"
  fi
  if [ -d ../zstd ] && [[ "${_CONFIG}" != *'nozstd'* ]]; then
    CFG+='-zstd'
    export ZSTD_PATH="../../zstd/${_PP}"
  fi

  h3=0

  if [ -n "${_OPENSSL}" ]; then
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

  if [ -d ../wolfssl ]; then
    CFG+='-wolfssl'
    export WOLFSSL_PATH="../../wolfssl/${_PP}"
    h3=1
  fi
  if [ -d ../mbedtls ]; then
    CFG+='-mbedtls'
    export MBEDTLS_PATH="../../mbedtls/${_PP}"
  fi

  if [ "${_OS}" = 'win' ]; then
    CFG+='-schannel'
  fi
  CPPFLAGS+=' -DHAS_ALPN'

# CPPFLAGS+=' -DCURL_CA_FALLBACK=1'

  if [ -d ../wolfssh ] && [ -d ../wolfssl ]; then
    CFG+='-wolfssh'
    export WOLFSSH_PATH="../../wolfssh/${_PP}"
  elif [ -d ../libssh ]; then
    CFG+='-libssh'
    export LIBSSH_PATH="../../libssh/${_PPS}"
    CPPFLAGS+=' -DLIBSSH_STATIC'
  elif [ -d ../libssh2 ]; then
    CFG+='-ssh2'
    export LIBSSH2_PATH="../../libssh2/${_PPS}"
  fi
  if [ -d ../nghttp2 ]; then
    CFG+='-nghttp2'
    export NGHTTP2_PATH="../../nghttp2/${_PP}"
    CPPFLAGS+=' -DNGHTTP2_STATICLIB'
  fi

  [[ "${_CONFIG}" != *'noh3'* ]] || h3=0

  if [ "${h3}" = '1' ] && [ -d ../nghttp3 ] && [ -d ../ngtcp2 ]; then
    CFG+='-nghttp3-ngtcp2'
    export NGHTTP3_PATH="../../nghttp3/${_PP}"
    CPPFLAGS+=' -DNGHTTP3_STATICLIB'
    export NGTCP2_PATH="../../ngtcp2/${_PPS}"
    CPPFLAGS+=' -DNGTCP2_STATICLIB'
  fi
  if [ -d ../cares ]; then
    CFG+='-ares'
    export LIBCARES_PATH="../../cares/${_PP}"
    CPPFLAGS+=' -DCARES_STATICLIB'
  fi
  if [ -d ../gsasl ]; then
    CFG+='-gsasl'
    export LIBGSASL_PATH="../../gsasl/${_PPS}"
  fi
  if [ -d ../libidn2 ]; then
    CFG+='-idn2'
    export LIBIDN2_PATH="../../libidn2/${_PP}"

    if [ -d ../libpsl ]; then
      CFG+='-psl'
      export LIBPSL_PATH="../../libpsl/${_PP}"
    fi

    if [ -d ../libiconv ]; then
      LDFLAGS+=" -L../../libiconv/${_PP}/lib"
      LIBS+=' -liconv'
    fi
    if [ -d ../libunistring ]; then
      LDFLAGS+=" -L../../libunistring/${_PP}/lib"
      LIBS+=' -lunistring'
    fi
  elif [[ "${_CONFIG}" != *'pico'* ]] && \
       [ "${_OS}" = 'win' ]; then
    CFG+='-winidn'
  fi

  [[ "${_CONFIG}" = *'noftp'* ]] && CPPFLAGS+=' -DCURL_DISABLE_FTP=1'

  CPPFLAGS+=' -DUSE_WEBSOCKETS'

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
    cp -f -p ./lib/*.map "${_PP}/${DYN_DIR}/"
  fi

  . ../curl-pkg.sh
)
