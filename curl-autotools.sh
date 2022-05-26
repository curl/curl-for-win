#!/bin/sh

# [AUTOTOOLS BROKEN, INCOMPLETE]

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

  # Skip building tests
# sed -i.bak 's| tests||g' ./Makefile.am

  if [ ! -f 'Makefile' ]; then
    autoreconf --force --install
    cp -f -p Makefile.dist Makefile
  fi

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

  export LDFLAGS="${_OPTM}"
  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # marking public libcurl functions as 'exported'. Useful to avoid the
  # chance of libcurl functions getting exported from final binaries when
  # linked against static libcurl lib.
  export CFLAGS='-fno-ident -O3 -DCURL_STATICLIB -DHAVE_ATOMIC -DHAVE_IOCTLSOCKET_FIONBIO -DHAVE_SOCKET -DUSE_UNIX_SOCKETS'
  ldonly=''

  if [ "${CC}" = 'mingw-clang' ]; then
    export CC='clang'
    if [ "${_OS}" != 'win' ]; then
      options="${options} --target=${_TRIPLET} --with-sysroot=${_SYSROOT}"
      LDFLAGS="${LDFLAGS} -target ${_TRIPLET} --sysroot ${_SYSROOT}"
      [ "${_OS}" = 'linux' ] && ldonly="${ldonly} -L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1)"
    fi
    export AR="${_CCPREFIX}ar"
    export NM="${_CCPREFIX}nm"
    export RANLIB="${_CCPREFIX}ranlib"
  else
    export CC="${_CCPREFIX}gcc -static-libgcc"
  fi

  CFLAGS="${LDFLAGS} ${CFLAGS}"
  LDFLAGS="${LDFLAGS}${ldonly}"
  [ "${_CPU}" = 'x86' ] && CFLAGS="${CFLAGS} -fno-asynchronous-unwind-tables"

  if false; then
    # TODO: Logic below is yet to be migrated to autotools

    export LDFLAGS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
    export CURL_LDFLAG_EXTRAS_EXE
    export CURL_LDFLAG_EXTRAS_DLL
    if [ "${_CPU}" = 'x86' ]; then
      CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,_mainCRTStartup'
      CURL_LDFLAG_EXTRAS_DLL=''
    else
      CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,mainCRTStartup'
      CURL_LDFLAG_EXTRAS_DLL='-Wl,--image-base,0x150000000'
      LDFLAGS="${LDFLAGS} -Wl,--high-entropy-va"
    fi

    # Disabled till we flesh out UNICODE support and document it enough to be
    # safe to use.
  # CFLAGS="${CFLAGS} -DUNICODE -D_UNICODE"
  # LDFLAGS="${LDFLAGS} -municode"

    if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
      CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,-Map,curl.map"
      CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,-Map,libcurl.map"
    fi

    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} libcurl.def"

    [ "${_CPU}" = 'x64' ] && export CURL_DLL_SUFFIX=-x64
    export CURL_DLL_A_SUFFIX=.dll
  fi

  # NOTE: root path with spaces will break all value with '$(pwd)'. But,
  #       autotools breaks on spaces anyway, so let us leave it like that.

  if [ -d ../zlib ]; then
    options="${options} --with-zlib=$(pwd)/../zlib/pkg/usr/local"
    # These seem to work better than --with-libz-prefix=:
    #CFLAGS="${CFLAGS} -I$(pwd)/../zlib/pkg/usr/local/include"
    #LDFLAGS="${LDFLAGS} -L$(pwd)/../zlib/pkg/usr/local/lib"
  else
    options="${options} --without-zlib"
  fi

  if [ -d ../brotli ]; then
    options="${options} --with-brotli=$(pwd)/../brotli/pkg/usr/local"
  else
    options="${options} --without-brotli"
  fi

  options="${options} --without-zstd"

  options="${options} --with-schannel"
  if [ -d ../libressl ]; then
    options="${options} --with-default-ssl-backend=openssl --with-openssl=$(pwd)/../libressl/pkg/usr/local"
  elif [ -d ../openssl-quic ]; then
    options="${options} --with-default-ssl-backend=openssl --with-openssl=$(pwd)/../openssl-quic/pkg/usr/local"
    # Workaround for 3.x deprecation warnings
    CFLAGS="${CFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
    LDFLAGS="${LDFLAGS} -bcrypt"
  elif [ -d ../openssl ]; then
    options="${options} --with-default-ssl-backend=openssl --with-openssl=$(pwd)/../openssl/pkg/usr/local"
    # Workaround for 3.x deprecation warnings
    CFLAGS="${CFLAGS} -DOPENSSL_SUPPRESS_DEPRECATED"
  else
    options="${options} --with-default-ssl-backend=schannel"
  fi

  options="${options} --without-gnutls --without-mbedtls --without-wolfssl --without-bearssl --without-rustls --without-nss --without-hyper"

  if [ -d ../libssh2 ]; then
    options="${options} --with-libssh2=$(pwd)/../libssh2/pkg/usr/local"
  else
    options="${options} --without-libssh2"
  fi

  options="${options} --without-libssh --without-wolfssh"
  options="${options} --without-librtmp"

  if [ -d ../libidn2 ]; then
    options="${options} --with-libidn2=$(pwd)/../libidn2/pkg/usr/local"
  else
    options="${options} --with-winidn"  # FIXME: path?
  fi

  if [ -d ../libgsasl ]; then
    options="${options} --with-libgsasl=$(pwd)/../libgsasl/pkg/usr/local"
  else
    options="${options} --without-libgsasl"
  fi

  options="${options} --without-libpsl"

  if [ -d ../nghttp2 ]; then
    options="${options} --with-nghttp2=$(pwd)/../libnghttp2/pkg/usr/local"
    CFLAGS="${CFLAGS} -DNGHTTP2_STATICLIB"
  else
    options="${options} --without-nghttp2"
  fi
  if false; then  # FIXME: autotools fails to find an "ngtcp2 pkg-config file"
  if [ -d ../nghttp3 ]; then
    options="${options} --with-nghttp3=$(pwd)/../libnghttp3/pkg/usr/local"
    CFLAGS="${CFLAGS} -DNGHTTP3_STATICLIB"
  else
    options="${options} --without-nghttp3"
  fi
  if [ -d ../ngtcp2 ]; then
    options="${options} --with-ngtcp2=$(pwd)/../libngtcp2/pkg/usr/local"
    CFLAGS="${CFLAGS} -DNGTCP2_STATICLIB"
  else
    options="${options} --without-ngtcp2"
  fi
  fi

  options="${options} --without-quiche --without-msh3"

  options="${options} --with-ldap-lib=wldap32"

#    --enable-unix-sockets \
#    --enable-socketpair \

  # shellcheck disable=SC2086
  ./configure ${options} \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-debug \
    --enable-optimize \
    --enable-symbol-hiding \
    --enable-static \
    --enable-shared \
    --disable-ares \
    --enable-http \
    --enable-ftp \
    --enable-file \
    --enable-ldap \
    --enable-ldaps \
    --disable-rtsp \
    --enable-proxy \
    --enable-dict \
    --enable-telnet \
    --enable-tftp \
    --enable-pop3 \
    --enable-imap \
    --enable-smb \
    --enable-smtp \
    --enable-gopher \
    --enable-mqtt \
    --enable-manual \
    --enable-libcurl-option \
    --enable-ipv6 \
    --disable-openssl-auto-load-config \
    --enable-verbose \
    --enable-sspi \
    --enable-crypto-auth \
    --enable-ntlm \
    --enable-tls-srp \
    --enable-cookies \
    --enable-http-auth \
    --enable-doh \
    --enable-mime \
    --enable-dateparse \
    --enable-netrc \
    --enable-progress-meter \
    --enable-dnsshuffle \
    --enable-get-easy-options \
    --enable-alt-svc \
    --enable-headers-api \
    --enable-hsts \
    --without-ca-path \
    --without-ca-bundle \
    --with-ca-fallback \
    --prefix=/usr/local \
    --silent
  make --jobs 2 clean >/dev/null
  make --jobs 2 install "DESTDIR=$(pwd)/pkg" # >/dev/null # V=1

  # DESTDIR= + --prefix=
  _pkg='.'

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

  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-all   ${_pkg}/src/*.exe
  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-all   ${_pkg}/lib/*.dll
  "${_CCPREFIX}strip" --preserve-dates --enable-deterministic-archives --strip-debug ${_pkg}/lib/*.a

  ../_peclean.py "${_ref}" ${_pkg}/src/*.exe
  ../_peclean.py "${_ref}" ${_pkg}/lib/*.dll

  ../_sign-code.sh "${_ref}" ${_pkg}/src/*.exe
  ../_sign-code.sh "${_ref}" ${_pkg}/lib/*.dll

  touch -c -r "${_ref}" ${_pkg}/src/*.exe
  touch -c -r "${_ref}" ${_pkg}/lib/*.dll
  touch -c -r "${_ref}" ${_pkg}/lib/*.def
  touch -c -r "${_ref}" ${_pkg}/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" ${_pkg}/src/*.map
    touch -c -r "${_ref}" ${_pkg}/lib/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers ${_pkg}/src/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers ${_pkg}/lib/*.dll | grep -a -E -i "(file format|dll name)"

  # Execute curl and compiled-in dependency code. This is not secure, but
  # the build process already requires executing external code
  # (e.g. configure scripts) on the build machine, so this will not make
  # it worse, except that it requires installing WINE on a compatible CPU
  # (and a QEMU setup on non-compatible ones). It would be best to extract
  # `--version` output directly from the binary as strings, but curl creates
  # most of these strings dynamically at runtime, so this is not possible
  # (as of curl 7.83.1).
  ${_WINE} ${_pkg}/src/curl.exe --version | tee "curl-${_CPU}.txt"

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
  cp -f -p ${_pkg}/src/*.exe        "${_DST}/bin/"
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
    cp -f -p ${_pkg}/src/*.map        "${_DST}/bin/"
    cp -f -p ${_pkg}/lib/*.map        "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
