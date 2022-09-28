#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-autotools//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  cache='configure-cache.txt'
  rm -f "${cache}"

  rm -r -f "${_PKGDIR}" "${_BLDDIR}-shared" "${_BLDDIR}-static"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  if [ ! -f 'configure' ] || \
     [ "${CURL_VER_}" = '7.85.0' ]; then
    autoreconf --force --install
  fi

  [ "${CW_DEV_CROSSMAKE_REPRO:-}" = '1' ] && export AR="${AR_NORMALIZE}"

  # tell libtool to allow building a shared library against static libs
  export lt_cv_deplibs_check_method='pass_all'

  for pass in shared static; do

    options="${_CONFIGURE_GLOBAL}"
    export CC="${_CC_GLOBAL}"
    export CFLAGS="${_CFLAGS_GLOBAL} -O3 -W -Wall"
    export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
    export RCFLAGS="${_RCFLAGS_GLOBAL}"
    export LDFLAGS="${_LDFLAGS_GLOBAL}"
    export LIBS="${_LIBS_GLOBAL}"

    CPPFLAGS="${CPPFLAGS} -DNDEBUG -DHAVE_PROCESS_H -DHAVE_INET_PTON -DHAVE_STRUCT_POLLFD"

    # configure: error: --enable-unix-sockets is not available on this platform!
    # due to non-portable verification method.
    CPPFLAGS="${CPPFLAGS} -DUSE_UNIX_SOCKETS"

    if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
      if [ "${pass}" = 'shared' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dll.tar"
      else
        LDFLAGS="${LDFLAGS} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-exe.tar"
      fi
    fi

    LDFLAGS="${LDFLAGS} -Wl,--nxcompat -Wl,--dynamicbase"
    if [ "${_CPU}" = 'x86' ]; then
      if [ "${pass}" = 'static' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--pic-executable,-e,_mainCRTStartup"
      fi
    else
      if [ "${pass}" = 'static' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--pic-executable,-e,mainCRTStartup"
      else
        LDFLAGS="${LDFLAGS} -Wl,--image-base,0x150000000"
      fi
      LDFLAGS="${LDFLAGS} -Wl,--high-entropy-va"
    fi

    if [ ! "${_BRANCH#*unicode*}" = "${_BRANCH}" ]; then
      CPPFLAGS="${CPPFLAGS} -DUNICODE -D_UNICODE"
      LDFLAGS="${LDFLAGS} -municode"
    fi

    if [ "${CW_MAP}" = '1' ]; then
      if [ "${pass}" = 'shared' ]; then
        _MAP_NAME="libcurl${_CURL_DLL_SUFFIX}.map"
      else
        _MAP_NAME='curl.map'
      fi
      LDFLAGS="${LDFLAGS} -Wl,-Map,${_MAP_NAME}"
    fi

    if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ] || \
       [ ! "${_BRANCH#*nano*}" = "${_BRANCH}" ]; then
      options="${options} --disable-alt-svc"
    else
      options="${options} --enable-alt-svc"
    fi

    if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} --disable-crypto-auth"
      options="${options} --disable-dict --disable-file --disable-gopher --disable-mqtt --disable-rtsp --disable-smb --disable-telnet --disable-tftp"
      options="${options} --disable-ftp"
      options="${options} --disable-imap --disable-pop3 --disable-smtp"
      options="${options} --disable-ldap --disable-ldaps --with-ldap-lib=wldap32"
    else
      options="${options} --enable-crypto-auth"
      options="${options} --enable-dict --enable-file --enable-gopher --enable-mqtt --enable-rtsp --enable-smb --enable-telnet --enable-tftp"
      if [ "${_BRANCH#*noftp*}" = "${_BRANCH}" ]; then
        options="${options} --enable-ftp"
      else
        options="${options} --disable-ftp"
      fi
      options="${options} --enable-imap --enable-pop3 --enable-smtp"
      options="${options} --enable-ldap --enable-ldaps --with-ldap-lib=wldap32"
    fi

    # NOTE: root path with spaces breaks all values with '${_TOP}'. But,
    #       autotools breaks on spaces anyway, so let us leave it like that.

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

    options="${options} --with-schannel"
    CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

    h3=0

    if [ -n "${_OPENSSL}" ]; then
      options="${options} --with-openssl=${_TOP}/${_OPENSSL}/${_PP}"
      options="${options} --disable-openssl-auto-load-config"
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        CPPFLAGS="${CPPFLAGS} -DCURL_BORINGSSL_VERSION=\\\"$(printf '%.8s' "${BORINGSSL_VER_}")\\\""
        options="${options} --disable-tls-srp"
        if [ "${_TOOLCHAIN}" = 'mingw-w64' ] && [ "${_CPU}" = 'x64' ] && [ "${_CRT}" = 'ucrt' ]; then  # FIXME
          LDFLAGS="${LDFLAGS} -Wl,-Bdynamic,-lpthread,-Bstatic"
        else
          LDFLAGS="${LDFLAGS} -Wl,-Bstatic,-lpthread,-Bdynamic"
        fi
        h3=1
      elif [ "${_OPENSSL}" = 'libressl' ]; then
        options="${options} --enable-tls-srp"
        LIBS="${LIBS} -lbcrypt"
      elif [ "${_OPENSSL}" = 'openssl-quic' ] || [ "${_OPENSSL}" = 'openssl' ]; then
        options="${options} --enable-tls-srp"
        LIBS="${LIBS} -lbcrypt"
        [ "${_OPENSSL}" = 'openssl-quic' ] && h3=1
      fi
    else
      options="${options} --disable-tls-srp"
    fi

    if [ -d ../wolfssl ]; then
      options="${options} --with-wolfssl=${_TOP}/wolfssl/${_PP}"
      h3=1
    else
      options="${options} --without-wolfssl"
    fi

    if [ -d ../mbedtls ]; then
      options="${options} --with-mbedtls=${_TOP}/mbedtls/${_PP}"
    else
      options="${options} --without-mbedtls"
    fi

    options="${options} --without-gnutls --without-bearssl --without-rustls --without-nss --without-hyper"

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
      LIBS="${LIBS} -lbcrypt"
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
    elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} --without-libidn2"
      options="${options} --with-winidn"
    fi

    if [ -d ../cares ]; then
      options="${options} --enable-ares=${_TOP}/cares/${_PP}"
      CPPFLAGS="${CPPFLAGS} -DCARES_STATICLIB"
    else
      options="${options} --disable-ares"
    fi

    if [ -d ../libgsasl ]; then
      options="${options} --with-libgsasl=${_TOP}/libgsasl/${_PP}"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/libgsasl/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/libgsasl/${_PP}/lib"
    else
      options="${options} --without-libgsasl"
    fi

    if [ -d ../nghttp2 ]; then
      options="${options} --with-nghttp2=${_TOP}/nghttp2/${_PP}"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP2_STATICLIB"
    else
      options="${options} --without-nghttp2"
    fi

    [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ] || h3=0

    # HTTP3 does not appear enabled in the configure summary.
    if [ "${h3}" = '1' ] && [ -d ../nghttp3 ] && [ -d ../ngtcp2 ]; then
      # Detection insists on having a pkg-config, so force feed everything manually.
      # This lib does not appear enabled in the configure summary.
      options="${options} --with-nghttp3=yes"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP3_STATICLIB -DUSE_NGHTTP3"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/nghttp3/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/nghttp3/${_PP}/lib"
      LIBS="${LIBS} -lnghttp3"

      # Detection insists on having a pkg-config, so force feed everything manually.
      # This lib does not appear enabled in the configure summary.
      options="${options} --with-ngtcp2=yes"
      CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB -DUSE_NGTCP2"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/ngtcp2/${_PP}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/ngtcp2/${_PP}/lib"
      LIBS="${LIBS} -lngtcp2"
      if [ "${_OPENSSL}" = 'boringssl' ]; then
        LIBS="${LIBS} -lngtcp2_crypto_boringssl"
      elif [ "${_OPENSSL}" = 'openssl-quic' ]; then
        LIBS="${LIBS} -lngtcp2_crypto_openssl"
      elif [ -d ../wolfssl ]; then
        LIBS="${LIBS} -lngtcp2_crypto_wolfssl"
      fi
    else
      options="${options} --without-nghttp3"
      options="${options} --without-ngtcp2"
    fi

    options="${options} --without-quiche --without-msh3"

    [ "${CURL_VER_}" != '7.85.0' ] && options="${options} --enable-websockets"

    if [ "${pass}" = 'shared' ]; then
      _DEF_NAME="libcurl${_CURL_DLL_SUFFIX}.def"
      LDFLAGS="${LDFLAGS} -Wl,--output-def,${_DEF_NAME}"
      CPPFLAGS="${CPPFLAGS} -DCURL_STATICLIB"

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
        --disable-debug \
        --disable-pthreads \
        --enable-symbol-hiding \
        --enable-headers-api \
        --enable-http \
        --enable-proxy \
        --enable-manual \
        --enable-libcurl-option \
        --enable-ipv6 \
        --enable-verbose \
        --enable-sspi \
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
      # Skip building shared version curl.exe. The build itself works, but
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

  # Build fixups

  chmod -x "${_pkg}"/lib/*.a

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
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    for file in docs/libcurl/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -a -v -E '(\.|/Makefile$)'; then
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

  if [ -n "${_OPENSSL}" ]; then
    cp -f -p scripts/mk-ca-bundle.pl  "${_DST}/"
    cp -f -p ../ca-bundle.crt         "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${CW_MAP}" = '1' ]; then
    cp -f -p "${_pkg}"/bin/*.map      "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
