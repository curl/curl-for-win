#!/bin/sh

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

if [ "${_OS}" = 'mac' ]; then
  sed() { gsed "$@"; }
fi

(
  cd "${_NAM}"  # mandatory component

  # Build

  rm -r -f pkg

  find . -name '*.a'   -delete
  find . -name '*.dll' -delete
  find . -name '*.def' -delete
  find . -name '*.map' -delete

  if [ ! -f 'Makefile' ]; then
    autoreconf --force --install
    cp -f -p Makefile.dist Makefile
  fi

  # patch autotools to not refuse to link a shared library against static libs
  sed -i.bak -E 's|^deplibs_check_method=.+|deplibs_check_method=pass_all|g' ./configure

  # autotools forces its -On option (gcc = -O2, clang = -Os) and removes custom
  # ones. We patch ./configure to customize it.
  sed -i.bak 's|flags_opt_yes="-O[s12]"|flags_opt_yes="-O3"|g' ./configure

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

  CURL_DLL_SUFFIX=''
  [ "${_CPU}" = 'x64' ] && CURL_DLL_SUFFIX="-${_CPU}"
  [ "${_CPU}" = 'a64' ] && CURL_DLL_SUFFIX="-${_CPU}"

  for pass in shared static; do

    options="${_CONFIGURE_GLOBAL}"
    export CC="${_CC_GLOBAL}"
    export CFLAGS="${_CFLAGS_GLOBAL} -W -Wall"
    export CPPFLAGS="${_CPPFLAGS_GLOBAL}"
    export LDFLAGS="${_LDFLAGS_GLOBAL}"
    export LIBS="${_LIBS_GLOBAL}"

    export RCFLAGS='--output-format coff -Iinclude'
    [ "${_CPU}" = 'x86' ] && RCFLAGS="${RCFLAGS} --target=pe-i386"
    [ "${_CPU}" = 'x64' ] && RCFLAGS="${RCFLAGS} --target=pe-x86-64"
  # [ "${_CPU}" = 'a64' ] && RCFLAGS="${RCFLAGS} --target=..."  # FIXME

    CPPFLAGS="${CPPFLAGS} -DNDEBUG -DHAVE_PROCESS_H"

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
      CPPFLAGS="${CPPFLAGS} -D_WIN32_WINNT=0x0501"  # For Windows XP compatibility
      if [ "${pass}" = 'static' ]; then
        LDFLAGS="${LDFLAGS} -Wl,--pic-executable,-e,_mainCRTStartup"
      fi
    else
      CPPFLAGS="${CPPFLAGS} -DHAVE_INET_PTON -DHAVE_STRUCT_POLLFD"
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
      if [ "${pass}" = 'shared' ]; then
        LDFLAGS="${LDFLAGS} -Wl,-Map,libcurl.map"
      else
        LDFLAGS="${LDFLAGS} -Wl,-Map,curl.map"
      fi
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

    if [ -d ../zlib ]; then
      options="${options} --with-zlib=${_TOP}/zlib/pkg${_PREFIX}"
    else
      options="${options} --without-zlib"
    fi

    if [ -d ../brotli ] && [ "${_BRANCH#*nobrotli*}" = "${_BRANCH}" ]; then
      options="${options} --with-brotli=${_TOP}/brotli/pkg${_PREFIX}"
      LDFLAGS="${LDFLAGS} -L${_TOP}/brotli/pkg${_PREFIX}/lib"
      LIBS="${LIBS} -lbrotlicommon"
    else
      options="${options} --without-brotli"
    fi

    options="${options} --without-zstd"

    options="${options} --with-schannel"
    CPPFLAGS="${CPPFLAGS} -DHAS_ALPN"

    if [ -d ../libressl ]; then
      options="${options} --with-openssl=${_TOP}/libressl/pkg${_PREFIX}"
      options="${options} --enable-tls-srp"
      LIBS="${LIBS} -lbcrypt"
    elif [ -d ../openssl-quic ]; then
      options="${options} --with-openssl=${_TOP}/openssl-quic/pkg${_PREFIX}"
      options="${options} --enable-tls-srp"
      LIBS="${LIBS} -lbcrypt"
    elif [ -d ../openssl ]; then
      options="${options} --with-openssl=${_TOP}/openssl/pkg${_PREFIX}"
      options="${options} --enable-tls-srp"
      LIBS="${LIBS} -lbcrypt"
    else
      options="${options} --disable-tls-srp"
    fi

    options="${options} --without-gnutls --without-mbedtls --without-wolfssl --without-bearssl --without-rustls --without-nss --without-hyper"

    if [ -d ../libssh2 ]; then
      options="${options} --with-libssh2=${_TOP}/libssh2/pkg${_PREFIX}"
      LIBS="${LIBS} -lbcrypt"
    else
      options="${options} --without-libssh2"
    fi

    options="${options} --without-libssh --without-wolfssh"
    options="${options} --without-librtmp"

    if [ -d ../libidn2 ]; then  # Also for Windows XP compatibility
      options="${options} --with-libidn2=${_TOP}/libidn2/pkg${_PREFIX}"
    elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
      options="${options} --without-libidn2"  # Prevent autotools picking up a non-cross copy
      options="${options} --with-winidn"
    fi

    if [ -d ../libgsasl ]; then
      options="${options} --with-libgsasl=${_TOP}/libgsasl/pkg${_PREFIX}"
      CPPFLAGS="${CPPFLAGS} -I${_TOP}/libgsasl/pkg${_PREFIX}/include"
      LDFLAGS="${LDFLAGS} -L${_TOP}/libgsasl/pkg${_PREFIX}/lib"
    else
      options="${options} --without-libgsasl"
    fi

    options="${options} --without-libpsl"

    if [ -d ../nghttp2 ]; then
      options="${options} --with-nghttp2=${_TOP}/nghttp2/pkg${_PREFIX}"
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
        CPPFLAGS="${CPPFLAGS} -I${_TOP}/nghttp3/pkg${_PREFIX}/include"
        LDFLAGS="${LDFLAGS} -L${_TOP}/nghttp3/pkg${_PREFIX}/lib"
        LIBS="${LIBS} -lnghttp3"
      else
        options="${options} --without-nghttp3"
      fi
      if [ -d ../ngtcp2 ]; then
        # Detection insists on having a pkg-config, so force feed everything manually.
        # This lib will not appear enabled in the configure summary.
        options="${options} --with-ngtcp2=yes"
        CPPFLAGS="${CPPFLAGS} -DNGTCP2_STATICLIB -DUSE_NGTCP2"
        CPPFLAGS="${CPPFLAGS} -I${_TOP}/ngtcp2/pkg${_PREFIX}/include"
        LDFLAGS="${LDFLAGS} -L${_TOP}/ngtcp2/pkg${_PREFIX}/lib"
        LIBS="${LIBS} -lngtcp2 -lngtcp2_crypto_openssl"
      else
        options="${options} --without-ngtcp2"
      fi
    fi

    options="${options} --without-quiche --without-msh3"

    if [ "${pass}" = 'shared' ]; then
      LDFLAGS="${LDFLAGS} -Wl,--output-def,libcurl${CURL_DLL_SUFFIX}.def"
      CPPFLAGS="${CPPFLAGS} -DCURL_STATICLIB"

      options="${options} --disable-static"
      options="${options} --enable-shared"
    else
      options="${options} --enable-static"
      options="${options} --disable-shared"
    fi

    # autotools forces its unixy DLL naming scheme. We prefer to use the same
    # as with the other curl build systems. The default value is derived from
    # `VERSIONINFO=` in lib/Makefile.am.
    sed -i.bak -E "s| soname_spec='\\\$libname.+| soname_spec='\\\$libname${CURL_DLL_SUFFIX}\\\$shared_ext'|g" ./configure

    # shellcheck disable=SC2086
    ./configure ${options} \
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
      --without-ca-fallback \
      "--prefix=${_PREFIX}"

    # NOTE: 'make clean' deletes src/tool_hugehelp.c and docs/curl.1. Next,
    #       'make' regenerates them, including the current date in curl.1,
    #       and breaking reproducibility. tool_hugehelp.c might also be
    #       reflowed/hyphened differently than the source distro, breaking
    #       reproducibility again. Skip the clean phase to resolve it. Do
    #       any cleaning manually as necessary.
    find . -name '*.o'   -delete
    find . -name '*.lo'  -delete
    find . -name '*.la'  -delete
    find . -name '*.lai' -delete
    find . -name '*.pc'  -delete
    find . -name '*.exe' -delete

    if [ "${pass}" = 'shared' ]; then

      # Compile resource
      # shellcheck disable=SC2086
      "${RC}" ${RCFLAGS} -i lib/libcurl.rc -o lib/libcurl.rc.res

      # Cannot add this linker option to LDFLAGS as-is, because it gets used
      # by ./configure tests and fails right away. This needs GNU sed.
      # Also add our compiled resource object.
      # shellcheck disable=SC2016
      sed -i.bak '/^LDFLAGS = /a LDFLAGS := $(LDFLAGS) -Wl,libcurl.rc.res -Wl,../libcurl.def' lib/Makefile

      # Skip building shared version curl.exe. The build itself works, but
      # then autotools tries to create its "ltwrapper", and fails. This only
      # seems to happen when building curl against more than one dependency.
      # I have found no way to skip building that component, even though
      # we do not need it. Skip this pass altogether.
      sed -i.bak -E 's|^SUBDIRS = .+|SUBDIRS = lib|g' ./Makefile
    else
      # Compile resource
      # shellcheck disable=SC2086
      "${RC}" ${RCFLAGS} -i src/curl.rc -o src/curl.rc.res -DCURL_EMBED_MANIFEST

      # Add our compiled resource object.
      # shellcheck disable=SC2016
      sed -i.bak '/^LDFLAGS = /a LDFLAGS := $(LDFLAGS) -Wl,curl.rc.res' src/Makefile

      sed -i.bak -E 's|^SUBDIRS = .+|SUBDIRS = lib src|g' ./Makefile
    fi

    make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1
  done

  # DESTDIR= + --prefix=
  _pkg="pkg${_PREFIX}"

  # Build fixups

  chmod -x "${_pkg}"/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    mv './lib/libcurl.map' "./lib/libcurl${CURL_DLL_SUFFIX}.map"
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
  if [ "${_LD}" = 'ld' ]; then
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-all   "${_pkg}"/bin/*.exe
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-all   "${_pkg}"/bin/*.dll
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.dll.a
  fi
  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.a

  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.exe
  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.dll

  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.exe
  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.dll

  touch -c -r "${_ref}" "${_pkg}"/bin/*.exe
  touch -c -r "${_ref}" "${_pkg}"/bin/*.dll
  touch -c -r "${_ref}" ./lib/*.def
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" ./src/*.map
    touch -c -r "${_ref}" ./lib/*.map
  fi

  # Tests

  "${_OBJDUMP}" --all-headers "${_pkg}"/bin/*.exe | grep -a -E -i "(file format|dll name)"
  "${_OBJDUMP}" --all-headers "${_pkg}"/bin/*.dll | grep -a -E -i "(file format|dll name)"

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
  cp -f -p ./lib/*.def                "${_DST}/bin/"
  cp -f -p "${_pkg}"/lib/*.a          "${_DST}/lib/"
  cp -f -p docs/*.md                  "${_DST}/docs/"
  cp -f -p CHANGES                    "${_DST}/CHANGES.txt"
  cp -f -p COPYING                    "${_DST}/COPYING.txt"
  cp -f -p README                     "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES              "${_DST}/RELEASE-NOTES.txt"

  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
    cp -f -p scripts/mk-ca-bundle.pl "${_DST}/"
    cp -f -p ../ca-bundle.crt        "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p ./src/*.map        "${_DST}/bin/"
    cp -f -p ./lib/*.map        "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
