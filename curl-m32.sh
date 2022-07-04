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

  # Set OS string to the autotools value. To test reproducibility across make systems.
  if [ -n "${CW_DEV_CROSSMAKE_REPRO:-}" ]; then
    # x86_64-pc-win32 ->
    {
      echo '#undef OS'
      echo '#define OS "x86_64-w64-mingw32"'
    } >> ./lib/config-win32.h
  fi

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

  export CROSSPREFIX="${_CCPREFIX}"
  export CURL_CC="${_CC_GLOBAL}"

  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # marking public libcurl functions as 'exported'. Useful to avoid the
  # chance of libcurl functions getting exported from final binaries when
  # linked against the static libcurl lib.
  export CURL_CFLAG_EXTRAS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL}"

  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_STATICLIB -DNDEBUG"
  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_STRTOK_R -DHAVE_FTRUNCATE -D_FILE_OFFSET_BITS=64"
  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_LIBGEN_H -DHAVE_BASENAME"
  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_SIGNAL -DHAVE_BOOL_T -DSIZEOF_OFF_T=8"
  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_STDBOOL_H -DHAVE_STRING_H -DHAVE_SETJMP_H"
  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DUSE_HEADERS_API"

  export CURL_LDFLAG_EXTRAS="${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} -Wl,--nxcompat -Wl,--dynamicbase"
  export CURL_LDFLAG_EXTRAS_EXE=''
  export CURL_LDFLAG_EXTRAS_DLL=''
  if [ "${_CPU}" = 'x86' ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -D_WIN32_WINNT=0x0501 -DHAVE_ATOMIC"  # For Windows XP compatibility
    CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,--pic-executable,-e,_mainCRTStartup"
  else
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_INET_PTON -DHAVE_INET_NTOP"
    CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,--pic-executable,-e,mainCRTStartup"
    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,--image-base,0x150000000"
    CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--high-entropy-va"
  fi

  if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ] || \
     [ ! "${_BRANCH#*nano*}" = "${_BRANCH}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_ALTSVC=1"
  fi

  if [ ! "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_CRYPTO_AUTH=1"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_DICT=1 -DCURL_DISABLE_FILE=1 -DCURL_DISABLE_GOPHER=1 -DCURL_DISABLE_MQTT=1 -DCURL_DISABLE_RTSP=1 -DCURL_DISABLE_SMB=1 -DCURL_DISABLE_TELNET=1 -DCURL_DISABLE_TFTP=1"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_FTP=1"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_IMAP=1 -DCURL_DISABLE_POP3=1 -DCURL_DISABLE_SMTP=1"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_LDAP=1 -DCURL_DISABLE_LDAPS=1"
  else
    options="${options}-ldaps"
  fi

  if [ ! "${_BRANCH#*unicode*}" = "${_BRANCH}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DUNICODE -D_UNICODE"
    CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -municode"
  fi

  export CURL_DLL_SUFFIX="${_CURL_DLL_SUFFIX}"
  export CURL_DLL_A_SUFFIX=.dll

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,-Map,curl.map"
    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,-Map,libcurl${_CURL_DLL_SUFFIX}.map"
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
      | sed -E 's|^ *\*? *([a-z_]+) *\(.+$|\1|g'
  } | grep -a -v '^$' | sort | tee -a libcurl.def
  CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} ../libcurl.def"

  # NOTE: Makefile.m32 automatically enables -zlib with -ssh2
  if [ -d ../zlib ]; then
    export ZLIB_PATH="../../zlib/${_PP}"
    options="${options}-zlib"

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

  if [ -d ../libressl ]; then
    export OPENSSL_PATH="../../libressl/${_PP}"
  elif [ -d ../openssl-quic ]; then
    export OPENSSL_PATH="../../openssl-quic/${_PP}"
    # Workaround for 3.x deprecation warnings
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DOPENSSL_SUPPRESS_DEPRECATED"
  elif [ -d ../openssl ]; then
    export OPENSSL_PATH="../../openssl/${_PP}"
    # Workaround for 3.x deprecation warnings
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DOPENSSL_SUPPRESS_DEPRECATED"
  fi
  if [ -n "${OPENSSL_PATH:-}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG"
    options="${options}-ssl"
    export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
    export OPENSSL_LIBPATH="${OPENSSL_PATH}/lib"
    export OPENSSL_LIBS='-lssl -lcrypto -lbcrypt'
  fi

  options="${options}-schannel"
  CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAS_ALPN"

  if [ -d ../libssh2 ]; then
    options="${options}-ssh2"
    export LIBSSH2_PATH="../../libssh2/${_PP}"
    CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -L${LIBSSH2_PATH}/lib"
  fi
  if [ -d ../nghttp2 ]; then
    options="${options}-nghttp2"
    export NGHTTP2_PATH="../../nghttp2/${_PP}"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP2_STATICLIB"
  fi
  if [ -d ../nghttp3 ] && [ "${_BRANCH#*noh3*}" = "${_BRANCH}" ]; then
    options="${options}-nghttp3-ngtcp2"
    export NGHTTP3_PATH="../../nghttp3/${_PP}"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP3_STATICLIB"
    export NGTCP2_PATH="../../ngtcp2/${_PP}"
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGTCP2_STATICLIB"
  fi
  if [ -d ../libgsasl ]; then
    options="${options}-gsasl"
    export LIBGSASL_PATH="../../libgsasl/${_PP}"
  fi
  if [ -d ../libidn2 ]; then  # Also for Windows XP compatibility
    options="${options}-idn2"
    export LIBIDN2_PATH="../../libidn2/${_PP}"
  elif [ "${_BRANCH#*pico*}" = "${_BRANCH}" ]; then
    options="${options}-winidn"
  fi

  [ "${_BRANCH#*noftp*}" != "${_BRANCH}" ] && CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_FTP=1"

  if [ "${CW_DEV_LLD_REPRODUCE:-}" = '1' ] && [ "${_LD}" = 'lld' ]; then
    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-dll.tar"
    CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,--reproduce=$(pwd)/$(basename "$0" .sh)-exe.tar"
  fi

  "${_MAKE}" --jobs=2 --directory=lib --makefile=Makefile.m32 clean
  "${_MAKE}" --jobs=2 --directory=src --makefile=Makefile.m32 clean

  "${_MAKE}" --jobs=2 --directory=lib --makefile=Makefile.m32 CFG="${options}"
  "${_MAKE}" --jobs=2 --directory=src --makefile=Makefile.m32 CFG="${options}"

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

  # binutils 2.38 has issues handling lld output:
  # - failing on implibs or creating corrupted output (depending on options).
  # - not stripping the .buildid section, which contains a timestamp.
  # LLVM's own llvm-objcopy does not seems to work with Windows binaries,
  # so we do .exe and .dll stripping via the -s linker option.
  if [ "${_LD}" = 'ld' ]; then
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-all   "${_pkg}"/src/*.exe
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-all   "${_pkg}"/lib/*.dll
    "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.dll.a
  fi
  "${_STRIP}" --preserve-dates --enable-deterministic-archives --strip-debug "${_pkg}"/lib/libcurl.a

  ../_peclean.py "${_ref}" "${_pkg}"/src/*.exe
  ../_peclean.py "${_ref}" "${_pkg}"/lib/*.dll

  ../_sign-code.sh "${_ref}" "${_pkg}"/src/*.exe
  ../_sign-code.sh "${_ref}" "${_pkg}"/lib/*.dll

  touch -c -r "${_ref}" "${_pkg}"/src/*.exe
  touch -c -r "${_ref}" "${_pkg}"/lib/*.dll
  touch -c -r "${_ref}" "${_pkg}"/lib/*.def
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" "${_pkg}"/src/*.map
    touch -c -r "${_ref}" "${_pkg}"/lib/*.map
  fi

  # Tests

  "${_OBJDUMP}" --all-headers "${_pkg}"/src/*.exe | grep -a -E -i "(file format|dll name)"
  "${_OBJDUMP}" --all-headers "${_pkg}"/lib/*.dll | grep -a -E -i "(file format|dll name)"

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

  if [ -d ../libressl ] || [ -d ../openssl ] || [ -d ../openssl-quic ]; then
    cp -f -p scripts/mk-ca-bundle.pl "${_DST}/"
    cp -f -p ../ca-bundle.crt        "${_DST}/bin/curl-ca-bundle.crt"
  fi

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p "${_pkg}"/src/*.map        "${_DST}/bin/"
    cp -f -p "${_pkg}"/lib/*.map        "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
