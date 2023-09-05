#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-autotools//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  cache='configure-cache.txt'
  rm -f "${cache}"

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}-shared" "${_BLDDIR:?}-static"

  [ -f 'configure' ] || autoreconf --force --install

  [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && export AR="${AR_NORMALIZE}"

  # tell libtool to allow building a shared library against static libs
  export lt_cv_deplibs_check_method='pass_all'

  for pass in shared static; do

    options="${_CONFIGURE_GLOBAL}"
    export CC="${_CC_GLOBAL}"
    export CFLAGS="${_CFLAGS_GLOBAL} -O3"
    export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
    export RCFLAGS="${_RCFLAGS_GLOBAL}"
    export LDFLAGS="${_LDFLAGS_GLOBAL}"
    export LIBS="${_LIBS_GLOBAL}"

    options="${options} --enable-unix-sockets"

    if [ ! "${_BRANCH#*werror*}" = "${_BRANCH}" ]; then
      options="${options} --enable-werror"
    fi

    if [ ! "${_BRANCH#*debug*}" = "${_BRANCH}" ]; then
      options="${options} --enable-debug"
    else
      options="${options} --disable-debug"
      CPPFLAGS="${CPPFLAGS} -DNDEBUG"
    fi

    if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
      if [ "${pass}" = 'shared' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dyn.tar"
      else
        LDFLAGS="${LDFLAGS} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-bin.tar"
      fi
    fi

    if [ "${pass}" = 'static' ]; then
      LDFLAGS="${LDFLAGS} ${_LDFLAGS_BIN_GLOBAL}"
    fi

    if [ "${_OS}" = 'win' ] && [ "${_BRANCH#*unicode*}" != "${_BRANCH}" ]; then
      CPPFLAGS="${CPPFLAGS} -Dmain=wmain"  # FIXME: upstream. https://github.com/curl/curl/issues/7229
      CPPFLAGS="${CPPFLAGS} -DUNICODE -D_UNICODE"
      LDFLAGS="${LDFLAGS} -municode"
    fi

    if [ "${CW_MAP}" = '1' ]; then
      if [ "${pass}" = 'shared' ]; then
        _MAP_NAME="libcurl${_CURL_DLL_SUFFIX}.map"
      else
        _MAP_NAME='curl.map'
      fi
      if [ "${_OS}" = 'mac' ]; then
        LDFLAGS="${LDFLAGS} -Wl,-map,${_MAP_NAME}"
      else
        LDFLAGS="${LDFLAGS} -Wl,-Map,${_MAP_NAME}"
      fi
    fi

    if [ ! "${_BRANCH#*bldtst*}" = "${_BRANCH}" ] || \
       [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ] || \
       [ ! "${_BRANCH#*nano*}" = "${_BRANCH}" ]; then
      options="${options} --disable-alt-svc"
    else
      options="${options} --enable-alt-svc"
    fi

    if [ ! "${_BRANCH#*bldtst*}" = "${_BRANCH}" ] || \
       [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} --disable-crypto-auth"
      options="${options} --disable-dict --disable-file --disable-gopher --disable-mqtt --disable-rtsp --disable-smb --disable-telnet --disable-tftp"
      options="${options} --disable-ftp"
      options="${options} --disable-imap --disable-pop3 --disable-smtp"
      options="${options} --disable-ldap --disable-ldaps"
    else
      options="${options} --enable-crypto-auth"
      options="${options} --enable-dict --enable-file --enable-gopher --enable-mqtt --enable-rtsp --enable-smb --enable-telnet --enable-tftp"
      if [ "${_BRANCH#*noftp*}" = "${_BRANCH}" ]; then
        options="${options} --enable-ftp"
      else
        options="${options} --disable-ftp"
      fi
      options="${options} --enable-imap --enable-pop3 --enable-smtp"
      if [ "${_OS}" = 'win' ]; then
        options="${options} --enable-ldap --enable-ldaps --with-ldap-lib=wldap32"
      else
        # ldap is auto-detected on mac, but without ldaps. Disable it
        # rather than offering an insecure-only solution. In certain configs
        # it also results in 'deprecated in macOS 10.11' compiler output.
        options="${options} --disable-ldap --disable-ldaps"
      fi
    fi

    # NOTE: root path with spaces breaks all values with '${_TOP}'. But,
    #       autotools breaks on spaces anyway, so we leave it like that.

    if [ -n "${_ZLIB}" ]; then
      options="${options} --with-zlib=${_TOP}/${_ZLIB}/${_PP}"
    else
      options="${options} --without-zlib"
    fi

    if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
      options="${options} --with-brotli=${_TOP}/brotli/${_PP}"
      LDFLAGS="${LDFLAGS} -L${_TOP}/brotli/${_PP}/lib"
      LIBS="${LIBS} -lbrotlicommon"
    else
      options="${options} --without-brotli"
    fi
    if [ -d ../zstd ] && [ "${_BRANCH#*nozstd*}" = "${_BRANCH}" ]; then
      options="${options} --with-zstd=${_TOP}/zstd/${_PP}"
      LDFLAGS="${LDFLAGS} -L${_TOP}/zstd/${_PP}/lib"
      LIBS="${LIBS} -lzstd"
    else
      options="${options} --without-zstd"
    fi

    h3=0

    mainssl=''  # openssl, wolfssl, mbedtls, schannel, secure-transport, gnutls, bearssl, rustls

    if [ -n "${_OPENSSL}" ]; then
      [ -n "${mainssl}" ] || mainssl='openssl'
      options="${options} --with-openssl=${_TOP}/${_OPENSSL}/${_PP}"
      options="${options} --disable-openssl-auto-load-config"
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        CPPFLAGS="${CPPFLAGS} -DCURL_BORINGSSL_VERSION=\\\"$(printf '%.8s' "${BORINGSSL_VER_}")\\\""
        if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
          LDFLAGS="${LDFLAGS} -Wl,-Bdynamic,-lpthread,-Bstatic"
        else
          LDFLAGS="${LDFLAGS} -Wl,-Bstatic,-lpthread,-Bdynamic"
        fi
        h3=1
      elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'libressl' ] || [ "${_OPENSSL}" = 'openssl' ]; then
        if [ "${_OS}" = 'win' ]; then
          LIBS="${LIBS} -lbcrypt"  # for auto-detection
        fi
        [ "${_OPENSSL}" = 'openssl' ] || h3=1
      fi
    fi

    if [ -d ../wolfssl ]; then
      [ -n "${mainssl}" ] || mainssl='wolfssl'
      options="${options} --with-wolfssl=${_TOP}/wolfssl/${_PP}"
      # for QUIC auto-detection
      CPPFLAGS="${CPPFLAGS} -DHAVE_UINTPTR_T"
      LIBS="${LIBS} -lcrypt32"
      h3=1
    else
      options="${options} --without-wolfssl"
    fi

    if [ -d ../mbedtls ]; then
      [ -n "${mainssl}" ] || mainssl='mbedtls'
      options="${options} --with-mbedtls=${_TOP}/mbedtls/${_PP}"
    else
      options="${options} --without-mbedtls"
    fi

    options="${options} --without-gnutls --without-bearssl --without-rustls --without-hyper"

    if [ "${_OS}" = 'win' ]; then
      options="${options} --with-schannel"
    elif [ "${_OS}" = 'mac' ] && [ "${_OSVER}" -lt '1015' ]; then
      # SecureTransport deprecated in 2019 (macOS 10.15 Catalina, iOS 13.0)
      options="${options} --with-secure-transport"
      # Without this, SecureTransport becomes the default TLS backend
      [ -n "${mainssl}" ] && options="${options} --with-default-ssl-backend=${mainssl}"
    elif [ -z "${mainssl}" ]; then
      options="${options} --without-ssl"
    fi
    CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

    if [ -d ../wolfssh ] && [ -d ../wolfssl ]; then
      options="${options} --with-wolfssh=${_TOP}/wolfssh/${_PP}"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/wolfssh/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/wolfssh/${_PP}/lib"
      options="${options} --without-libssh"
      options="${options} --without-libssh2"
    elif [ -d ../libssh ]; then
      options="${options} --with-libssh=${_TOP}/libssh/${_PP}"
      options="${options} --without-wolfssh"
      options="${options} --without-libssh2"
      CPPFLAGS="${CPPFLAGS} -DLIBSSH_STATIC"
    elif [ -d ../libssh2 ]; then
      options="${options} --with-libssh2=${_TOP}/libssh2/${_PP}"
      options="${options} --without-wolfssh"
      options="${options} --without-libssh"
      if [ "${_OS}" = 'win' ]; then
        LIBS="${LIBS} -lbcrypt"  # for auto-detection

        # Workaround for libssh2 1.11.0 regression:
        # Omit __declspec(dllimport) with libssh2 1.11.0 to link statically
        [ "${LIBSSH2_VER_}" = '1.11.0' ] && CPPFLAGS="${CPPFLAGS} -DLIBSSH2_API="
      fi
    else
      options="${options} --without-wolfssh"
      options="${options} --without-libssh"
      options="${options} --without-libssh2"
    fi

    options="${options} --without-librtmp"

    if [ -d ../libidn2 ]; then
      options="${options} --with-libidn2=${_TOP}/libidn2/${_PP}"
      LDFLAGS="${LDFLAGS} -L${_TOP}/libidn2/${_PP}/lib"
      LIBS="${LIBS} -lidn2"

      if [ -d ../libpsl ]; then
        options="${options} --with-libpsl=${_TOP}/libpsl/${_PP}"
        CPPFLAGS="${CPPFLAGS} -I${_TOP}/libpsl/${_PP}/include"
        LDFLAGS="${LDFLAGS} -L${_TOP}/libpsl/${_PP}/lib"
        LIBS="${LIBS} -lpsl"
      else
        options="${options} --without-libpsl"
      fi

      if [ -d ../libiconv ]; then
        LDFLAGS="${LDFLAGS} -L${_TOP}/libiconv/${_PP}/lib"
        LIBS="${LIBS} -liconv"
      fi
      if [ -d ../libunistring ]; then
        LDFLAGS="${LDFLAGS} -L${_TOP}/libunistring/${_PP}/lib"
        LIBS="${LIBS} -lunistring"
      fi
    else
      options="${options} --without-libidn2"
      options="${options} --without-libpsl"
      if [ "${_BRANCH#*pico*}" = "${_BRANCH}" ] && \
         [ "${_OS}" = 'win' ]; then
        options="${options} --with-winidn"
      fi
    fi

    if [ -d ../cares ]; then
      options="${options} --enable-ares=${_TOP}/cares/${_PP}"
      CPPFLAGS="${CPPFLAGS} -DCARES_STATICLIB"
    else
      options="${options} --disable-ares"
    fi

    if [ -d ../gsasl ]; then
      options="${options} --with-libgsasl=${_TOP}/gsasl/${_PP}"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/gsasl/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/gsasl/${_PP}/lib"
    else
      options="${options} --without-libgsasl"
      if [ "${_OS}" = 'mac' ]; then
        # GSS API deprecated in 2012-2013 (OS X 10.8 Mountain Lion / 10.9 Mavericks, iOS 7.0)
      # options="${options} --with-gssapi"
        :
      fi
    fi

    if [ -d ../nghttp2 ]; then
      options="${options} --with-nghttp2=${_TOP}/nghttp2/${_PP}"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP2_STATICLIB"
    else
      options="${options} --without-nghttp2"
    fi

    [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ] || h3=0

    # We enable HTTP/3 manually, so it shows up "disabled" in 'configure summary'.
    if [ "${h3}" = '1' ] && [ -d ../nghttp3 ] && [ -d ../ngtcp2 ]; then
      # Detection insists on having a pkg-config, so force feed everything manually.
      # We enable this lib manually, so it shows up "disabled" in 'configure summary'.
      options="${options} --with-nghttp3=yes"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP3_STATICLIB -DUSE_NGHTTP3"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/nghttp3/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/nghttp3/${_PP}/lib"
      LIBS="${LIBS} -lnghttp3"

      # Detection insists on having a pkg-config, so force feed everything manually.
      # We enable this lib manually, so it shows up "disabled" in 'configure summary'.
      options="${options} --with-ngtcp2=yes"
      CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB -DUSE_NGTCP2"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/ngtcp2/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/ngtcp2/${_PP}/lib"
      LIBS="${LIBS} -lngtcp2"
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        LIBS="${LIBS} -lngtcp2_crypto_boringssl"
      elif [ "${_OPENSSL}" = 'quictls' ] || [ "${_OPENSSL}" = 'libressl' ]; then
        LIBS="${LIBS} -lngtcp2_crypto_quictls"
      elif [ -d ../wolfssl ]; then
        LIBS="${LIBS} -lngtcp2_crypto_wolfssl"
      fi
    else
      options="${options} --without-nghttp3"
      options="${options} --without-ngtcp2"
    fi

    if [ "${_OS}" = 'win' ]; then
      options="${options} --enable-sspi"
    fi

    options="${options} --without-quiche --without-msh3"

    options="${options} --enable-threaded-resolver"
    if [ "${_OS}" = 'win' ]; then
      options="${options} --disable-pthreads"
    else
      options="${options} --enable-pthreads"
    fi

    options="${options} --enable-websockets"

    if [ "${pass}" = 'shared' ]; then
      if [ "${_OS}" = 'win' ]; then
        _DEF_NAME="libcurl${_CURL_DLL_SUFFIX}.def"
        LDFLAGS="${LDFLAGS} -Wl,--output-def,${_DEF_NAME}"
      fi

      options="${options} --disable-static"
      options="${options} --enable-shared"
    else
      options="${options} --enable-static"
      options="${options} --disable-shared"
    fi

    if [ -f "${cache}" ]; then
      grep -a -v -E '_env_(CPPFLAGS|LDFLAGS)_' "${cache}" > "${cache}.new"
      mv "${cache}.new" "${cache}"
    fi

    options="${options} --cache-file=../${cache}"

    (
      mkdir "${_BLDDIR}-${pass}"; cd "${_BLDDIR}-${pass}"
      # shellcheck disable=SC2086
      ../configure ${options} \
        --disable-tls-srp \
        --enable-warnings \
        --enable-symbol-hiding \
        --enable-http \
        --enable-proxy \
        --enable-manual \
        --enable-libcurl-option \
        --enable-ipv6 \
        --enable-verbose \
        --enable-ntlm \
        --enable-cookies \
        --enable-http-auth \
        --enable-doh \
        --enable-mime \
        --enable-dateparse \
        --enable-netrc \
        --enable-progress-meter \
        --enable-dnsshuffle \
        --enable-get-easy-options \
        --enable-hsts \
        --without-ca-path \
        --without-ca-bundle \
        --without-ca-fallback
    )

    # NOTE: 'make clean' deletes src/tool_hugehelp.c and docs/curl.1. Next,
    #       'make' regenerates them, including the current date in curl.1,
    #       and breaking reproducibility. tool_hugehelp.c might also be
    #       reflowed/hyphened differently than the source distro, breaking
    #       reproducibility again. Skip the clean phase to resolve it.

    if [ "${pass}" = 'shared' ]; then
      # Skip building shared version curl tool. The build itself works, but
      # then autotools tries to create its "ltwrapper", and fails. This only
      # seems to happen when building curl against more than one dependency.
      # I have found no way to skip building that component, even though
      # we do not need it. Skip this pass altogether.
      VERSIONINFO='-avoid-version'
      [ -n "${_CURL_DLL_SUFFIX_NODASH}" ] && VERSIONINFO="-release '${_CURL_DLL_SUFFIX_NODASH}' ${VERSIONINFO}"
      make "VERSIONINFO=${VERSIONINFO}" \
        --directory="${_BLDDIR}-${pass}/lib" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1
    else
      make --directory="${_BLDDIR}-${pass}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}" # >/dev/null # V=1
    fi

    # Manual copy to DESTDIR

    if [ "${_OS}" = 'win' ] && [ "${pass}" = 'shared' ]; then
      cp -p "${_BLDDIR}-${pass}/lib/${_DEF_NAME}" "${_PP}"/bin/
    fi

    if [ "${CW_MAP}" = '1' ]; then
      if [ "${pass}" = 'shared' ]; then
        cp -p "${_BLDDIR}-${pass}/lib/${_MAP_NAME}" "${_PP}/${DYN_DIR}/"
      else
        cp -p "${_BLDDIR}-${pass}/src/${_MAP_NAME}" "${_PP}"/bin/
      fi
    fi
  done

  # Build fixups

  chmod -x "${_PP}"/lib/*.a

  . ../curl-pkg.sh
)
