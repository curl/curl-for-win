#!/bin/sh

# [SHARED BUILD (DLL) BROKEN]

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-autotools//')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  # Cross-tasks

  [ "${_OS}" != 'win' ] && options="--build=${_CROSS_HOST} --host=${_TRIPLET}"

  # Build

  rm -r -f pkg

  find . -name '*.dll' -delete
  find . -name '*.def' -delete

  # Skip building tests in non-cross-build cases
  sed -i.bak 's| tests packages| packages|g' ./Makefile.am

  if [ ! -f 'Makefile' ]; then
    autoreconf --force --install
    cp -f -p Makefile.dist Makefile
  fi

  # For 'shared' builds, create fake .libs to pass libtool's test for implibs.
  for fn in advapi32 crypt32 wldap32 ws2_32 normaliz ucrt z; do
    if [ "${fn}" = 'ucrt' ] || \
       [ "${fn}" = 'z' ]; then
      fnt=advapi32  # Any implib will do here.
    else
      fnt="${fn}"
    fi
    ln -s -f "${_SYSROOT}/${_TRIPLET}/lib/lib${fnt}.a" "../lib${fn}.lib"
  done

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

  for pass in static; do  # FIXME: 'shared' broken.

    export LDFLAGS="${_OPTM}"
    # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
    # marking public libcurl functions as 'exported'. Useful to avoid the
    # chance of libcurl functions getting exported from final binaries when
    # linked against static libcurl lib.
    export CFLAGS='-fno-ident -O3'
    export CPPFLAGS='-DCURL_STATICLIB -DHAVE_ATOMIC -DHAVE_IOCTLSOCKET_FIONBIO -DHAVE_SOCKET'
    export LIBS=''
    ldonly=''

    # configure: error: --enable-unix-sockets is not available on this platform!
    # due to non-portable verification method.
    CPPFLAGS="${CPPFLAGS} -DUSE_UNIX_SOCKETS"

    uselld=0
    if [ "${_CRT}" = 'ucrt' ]; then
      if [ "${_CC}" = 'clang' ]; then
        ldonly="${ldonly} -fuse-ld=lld -s"
        uselld=1
      else
        ldonly="${ldonly} -specs=${_GCCSPECS}"
      fi
      CPPFLAGS="${CPPFLAGS} -D_UCRT"
      LIBS="${LIBS} -lucrt"
    fi

    if [ "${_CC}" = 'clang' ]; then
      export CC='clang'
      if [ "${_OS}" != 'win' ]; then
        options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
        LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
        [ "${_OS}" = 'linux' ] && ldonly="${ldonly} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
      fi
      export AR="${_CCPREFIX}ar"
      export LD="${_CCPREFIX}ld"
      export NM="${_CCPREFIX}nm"
      export RANLIB="${_CCPREFIX}ranlib"
    else
      export CC="${_CCPREFIX}gcc -static-libgcc"
    fi

    CFLAGS="${LDFLAGS} ${CFLAGS}"
    LDFLAGS="${LDFLAGS}${ldonly}"
    [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"

    LDFLAGS="${LDFLAGS} -Wl,--nxcompat -Wl,--dynamicbase"
    if [ "${_CPU}" = 'x86' ]; then
      CPPFLAGS="${CPPFLAGS} -D_WIN32_WINNT=0x0501"  # For Windows XP compatibility
      if [ "${pass}" = 'static' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--pic-executable,-e,_mainCRTStartup"
      fi
    else
      CPPFLAGS="${CPPFLAGS} -DHAVE_INET_PTON"
      if [ "${pass}" = 'static' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--pic-executable,-e,mainCRTStartup"
      else
        LDFLAGS="${LDFLAGS} -Wl,--image-base,0x150000000"
      fi
      LDFLAGS="${LDFLAGS} -Wl,--high-entropy-va"
    fi

    # Disabled till we flesh out UNICODE support and document it enough to be
    # safe to use.
  # CPPFLAGS="${CPPFLAGS} -DUNICODE -D_UNICODE"
  # LDFLAGS="${LDFLAGS} -municode"

    if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
      if [ "${pass}" = 'static' ]; then
        LDFLAGS="${LDFLAGS} -Wl,-Map,curl.map"
      else
        LDFLAGS="${LDFLAGS} -Wl,-Map,libcurl.map"
      fi
    fi

    if [ "${pass}" = 'shared' ]; then
      # FIXME: This breaks autotools pre-checks. Our exports will always be
      # missing for test snippets. How to pass this to the actual linking
      # command? We likely have to solve this differently.
      #LDFLAGS="${LDFLAGS} libcurl.def"
      :
    fi

    # FIXME:
    [ "${_CPU}" = 'x64' ] && export CURL_DLL_SUFFIX="-${_CPU}"
    [ "${_CPU}" = 'a64' ] && export CURL_DLL_SUFFIX="-${_CPU}"

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

    # NOTE: root path with spaces breaks all values with '$(pwd)'. But,
    #       autotools breaks on spaces anyway, so let us leave it like that.

    if [ -d ../zlib ]; then
      options="${options} --with-zlib=$(pwd)/../zlib/pkg/usr/local"
    else
      options="${options} --without-zlib"
    fi

    if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
      options="${options} --with-brotli=$(pwd)/../brotli/pkg/usr/local"
      LDFLAGS="${LDFLAGS} -L$(pwd)/../brotli/pkg/usr/local/lib"
      LIBS="${LIBS} -lbrotlicommon"
    else
      options="${options} --without-brotli"
    fi

    options="${options} --without-zstd"

    options="${options} --with-schannel"
    CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

    if [ -d ../libressl ]; then
      options="${options} --with-default-ssl-backend=openssl --with-openssl=$(pwd)/../libressl/pkg/usr/local"
      options="${options} --enable-tls-srp"
      LIBS="${LIBS} -lbcrypt"
    elif [ -d ../openssl-quic ]; then
      options="${options} --with-default-ssl-backend=openssl --with-openssl=$(pwd)/../openssl-quic/pkg/usr/local"
      options="${options} --enable-tls-srp"
      # Workaround for 3.x deprecation warnings
      CPPFLAGS="${CPPFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
      LIBS="${LIBS} -lbcrypt"
    elif [ -d ../openssl ]; then
      options="${options} --with-default-ssl-backend=openssl --with-openssl=$(pwd)/../openssl/pkg/usr/local"
      options="${options} --enable-tls-srp"
      # Workaround for 3.x deprecation warnings
      CPPFLAGS="${CPPFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
      LIBS="${LIBS} -lbcrypt"
    else
      options="${options} --with-default-ssl-backend=schannel"
      options="${options} --disable-tls-srp"
    fi

    options="${options} --without-gnutls --without-mbedtls --without-wolfssl --without-bearssl --without-rustls --without-nss --without-hyper"

    if [ -d ../libssh2 ]; then
      options="${options} --with-libssh2=$(pwd)/../libssh2/pkg/usr/local"
      LIBS="${LIBS} -lbcrypt"
    else
      options="${options} --without-libssh2"
    fi

    options="${options} --without-libssh --without-wolfssh"
    options="${options} --without-librtmp"

    if [ -d ../libidn2 ]; then  # Also for Windows XP compatibility
      options="${options} --with-libidn2=$(pwd)/../libidn2/pkg/usr/local"
    elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} --without-libidn2"  # Prevent autotools picking up a non-cross copy
      options="${options} --with-winidn"
    fi

    if [ -d ../libgsasl ]; then
      options="${options} --with-libgsasl=$(pwd)/../libgsasl/pkg/usr/local"
      CFLAGS="${CFLAGS} -I$(pwd)/../libgsasl/pkg/usr/local/include"
      LDFLAGS="${LDFLAGS} -L$(pwd)/../libgsasl/pkg/usr/local/lib"
    else
      options="${options} --without-libgsasl"
    fi

    options="${options} --without-libpsl"

    if [ -d ../nghttp2 ]; then
      options="${options} --with-nghttp2=$(pwd)/../nghttp2/pkg/usr/local"
      CPPFLAGS="${CPPFLAGS} -DNGHTTP2_STATICLIB"
    else
      options="${options} --without-nghttp2"
    fi
    if [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
      if [ -d ../nghttp3 ]; then
        # Detection insists on having a pkg-config, so force feed everything manually.
        # This lib will not appear enabled in the configure summary.
        options="${options} --with-nghttp3=yes"
        CPPFLAGS="${CPPFLAGS} -DNGHTTP3_STATICLIB -DUSE_NGHTTP3"
        CFLAGS="${CFLAGS} -I$(pwd)/../nghttp3/pkg/usr/local/include"
        LDFLAGS="${LDFLAGS} -L$(pwd)/../nghttp3/pkg/usr/local/lib"
        LIBS="${LIBS} -lnghttp3"
      else
        options="${options} --without-nghttp3"
      fi
      if [ -d ../ngtcp2 ]; then
        # Detection insists on having a pkg-config, so force feed everything manually.
        # This lib will not appear enabled in the configure summary.
        options="${options} --with-ngtcp2=yes"
        CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB -DUSE_NGTCP2"
        CFLAGS="${CFLAGS} -I$(pwd)/../ngtcp2/pkg/usr/local/include"
        LDFLAGS="${LDFLAGS} -L$(pwd)/../ngtcp2/pkg/usr/local/lib"
        LIBS="${LIBS} -lngtcp2 -lngtcp2_crypto_openssl"
      else
        options="${options} --without-ngtcp2"
      fi
    fi

    options="${options} --without-quiche --without-msh3"

    if [ "${pass}" = 'static' ]; then
      options="${options} --enable-static"
      options="${options} --disable-shared"
    else
      options="${options} --disable-static"
      options="${options} --enable-shared"

      # Ugly hack to make libtool find what is wants when doing checks
      # before attempting to link a DLL. We put implibs here with all the
      # names it needs. This complements the .lib names symlinked to .a files.
      LDFLAGS="${LDFLAGS} -L$(pwd)/.."

      # FIXME: Not sure why this was necessary to find Windows implibs.
      LDFLAGS="${LDFLAGS} -L${_SYSROOT}/${_TRIPLET}/lib"
    fi

    # shellcheck disable=SC2086
    ./configure ${options} \
      --disable-dependency-tracking \
      --disable-silent-rules \
      --disable-debug \
      --disable-pthreads \
      --enable-optimize \
      --enable-symbol-hiding \
      --enable-headers-api \
      --disable-ares \
      --enable-http \
      --enable-proxy \
      --enable-manual \
      --enable-libcurl-option \
      --enable-ipv6 \
      --disable-openssl-auto-load-config \
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
      --with-ca-fallback \
      --prefix=/usr/local \
      --silent
    make --jobs 2 clean >/dev/null
    make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1
  done

  # DESTDIR= + --prefix=
  _pkg='pkg/usr/local'

  # Build fixups for clang

  # 'configure' misdetects CC=clang as MSVC and then uses '.lib'
  # extension. Rename these to '.a':
  if [ -f "${_pkg}/lib/libcurl.lib" ]; then
    sed -i.bak "s|\.lib'$|.a'|g" "${_pkg}/lib/libcurl.la"
    mv "${_pkg}/lib/libcurl.lib" "${_pkg}/lib/libcurl.a"
  fi

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
    "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-all   ${_pkg}/lib/*.dll
    "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/libcurl.dll.a
  fi
  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/libcurl.a

  ../_peclean.py "${_ref}" ${_pkg}/bin/*.exe
  ../_peclean.py "${_ref}" ${_pkg}/lib/*.dll

  ../_sign-code.sh "${_ref}" ${_pkg}/bin/*.exe
  ../_sign-code.sh "${_ref}" ${_pkg}/lib/*.dll

  touch -c -r "${_ref}" ${_pkg}/bin/*.exe
  touch -c -r "${_ref}" ${_pkg}/lib/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/*.def
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" ${_pkg}/bin/*.map
    touch -c -r "${_ref}" ${_pkg}/lib/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers ${_pkg}/bin/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers ${_pkg}/lib/*.dll | grep -a -E -i "(file format|dll name)"

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
  cp -f -p ${_pkg}/lib/*.dll        "${_DST}/bin/"
  cp -f -p ${_pkg}/lib/*.def        "${_DST}/bin/"
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
    cp -f -p ${_pkg}/bin/*.map        "${_DST}/bin/"
    cp -f -p ${_pkg}/lib/*.map        "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
