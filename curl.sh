#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}"  # mandatory component

  # Prepare build

  find . -name '*.dll' -delete
  find . -name '*.def' -delete

  if [ ! -f 'Makefile' ]; then
    autoreconf --force --install
    cp -f -p Makefile.dist Makefile
  fi

  # Build

  options='mingw32-ipv6-sspi-ldaps-srp'

  export ARCH
  [ "${_CPU}" = 'x86' ] && ARCH="w32"
  [ "${_CPU}" = 'x64' ] && ARCH="w64"

  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # public libcurl functions being marked as 'exported'. It is useful to
  # avoid the chance of libcurl functions getting exported from final
  # binaries when linked against static libcurl lib.
  export CURL_CFLAG_EXTRAS='-DCURL_STATICLIB -DCURL_ENABLE_MQTT -fno-ident -DHAVE_ATOMIC'
  [ "${_CPU}" = 'x86' ] && CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"
  export CURL_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
  export CURL_LDFLAG_EXTRAS_EXE
  export CURL_LDFLAG_EXTRAS_DLL
  if [ "${_CPU}" = 'x86' ]; then
    CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,_mainCRTStartup'
    CURL_LDFLAG_EXTRAS_DLL=''
  else
    CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,mainCRTStartup'
    CURL_LDFLAG_EXTRAS_DLL='-Wl,--image-base,0x150000000'
    CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--high-entropy-va"
  fi

  # Disabled till UNICODE is fleshed out and documented enough to be safe
  # to use.
# CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DUNICODE -D_UNICODE"
# CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -municode"

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    CURL_LDFLAG_EXTRAS_EXE="${CURL_LDFLAG_EXTRAS_EXE} -Wl,-Map,curl.map"
    CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} -Wl,-Map,libcurl.map"
  fi

  # Generate .def file for libcurl by parsing curl headers.
  # Useful to limit .dll exports to libcurl functions meant to be exported.
  # Without this, the default linker logic kicks in, whereas every public
  # function is exported if none is marked for export explicitly. This
  # leads to exporting every libcurl public function, as well as any other
  # ones from statically linked dependencies, resulting in a larger .dll,
  # an inflated implib and a non-standard list of exported functions.
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

  if [ -d ../zlibng ]; then
    export ZLIB_PATH=../../zlibng/pkg/usr/local
  else
    export ZLIB_PATH=../../zlib/pkg/usr/local
  fi
  options="${options}-zlib"
  if [ -d ../brotli ]; then
    options="${options}-brotli"
    export BROTLI_PATH=../../brotli/pkg/usr/local
    export BROTLI_LIBS='-Wl,-Bstatic -lbrotlidec-static -lbrotlicommon-static -Wl,-Bdynamic'
  fi

  [ -d ../openssl ] && export OPENSSL_PATH=../../openssl
  if [ -n "${OPENSSL_PATH:-}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG"
    # Workaround for deprecation warnings from the curl autoconf logic
    if [ "$(echo "${OPENSSL_VER_}" | cut -c -2)" = '3.' ]; then
      CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DOPENSSL_SUPPRESS_DEPRECATED -DHAVE_OPENSSL_VERSION"
    fi
    options="${options}-ssl"
    export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
    export OPENSSL_LIBPATH="${OPENSSL_PATH}"
    export OPENSSL_LIBS='-lssl -lcrypto'
  fi
  options="${options}-schannel-winssl"
  if [ -d ../libssh2 ]; then
    options="${options}-ssh2"
    export LIBSSH2_PATH=../../libssh2
  fi
  if [ -d ../nghttp2 ]; then
    options="${options}-nghttp2"
    export NGHTTP2_PATH=../../nghttp2/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP2_STATICLIB"
  fi
  if [ -d ../nghttp3 ]; then
    options="${options}-nghttp3-ngtcp2"
    export NGHTTP3_PATH=../../nghttp3/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP3_STATICLIB"
    export NGTCP2_PATH=../../ngtcp2/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGTCP2_STATICLIB"
  fi
  if [ -d ../libgsasl ]; then
    options="${options}-gsasl"
    export LIBGSASL_PATH=../../libgsasl/pkg/usr/local
  fi
  if [ -d ../libidn2 ]; then
    options="${options}-idn2"
    export LIBIDN2_PATH=../../libidn2/pkg/usr/local
  else
    options="${options}-winidn"
  fi

  [ "${_CPU}" = 'x64' ] && export CURL_DLL_SUFFIX=-x64
  export CURL_DLL_A_SUFFIX=.dll

  # Make sure to link zlib (and only zlib) in static mode when building
  # `libcurl.dll`, so that it would not depend on a `zlib1.dll`.
  # In some build environments (such as MSYS2), `libz.dll.a` is also offered
  # along with `libz.a` causing the linker to pick up the shared library.
  export DLL_LIBS='-Wl,-Bstatic -lz -Wl,-Bdynamic'

  # Link further libs to libcurl DLL in static mode by
  # deleting their implibs:
  rm -f \
    '../libssh2/win32/libssh2.dll.a' \
    '../libidn2/pkg/usr/local/lib/libidn2.dll.a' \
    '../libgsasl/pkg/usr/local/lib/libgsasl.dll.a' \
    '../openssl/libcrypto.dll.a' \
    '../openssl/libssl.dll.a'

  export CROSSPREFIX="${_CCPREFIX}"

  if [ "${CC}" = 'mingw-clang' ]; then
  # CURL_CFLAG_EXTRAS="-mretpoline ${CURL_CFLAG_EXTRAS}"
  # CURL_CFLAG_EXTRAS="-mspeculative-load-hardening ${CURL_CFLAG_EXTRAS}"
    export CURL_CC="clang${_CCSUFFIX}"
    if [ "${_OS}" != 'win' ]; then
      CURL_CFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${CURL_CFLAG_EXTRAS}"
      [ "${_OS}" = 'linux' ] && CURL_LDFLAG_EXTRAS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${CURL_LDFLAG_EXTRAS}"
      CURL_LDFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${CURL_LDFLAG_EXTRAS}"
    fi
    # This does not work yet, due to:
    #   /usr/local/bin/x86_64-w64-mingw32-ld: asyn-thread.o:asyn-thread.c:(.rdata$.refptr.__guard_dispatch_icall_fptr[.refptr.__guard_dispatch_icall_fptr]+0x0): undefined reference to `__guard_dispatch_icall_fptr'
  # CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -Xclang -cfguard"
  # CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Xlinker -guard:cf"
  fi

  ${_MAKE} -j 2 mingw32-clean
  ${_MAKE} -j 2 "${options}"

  # Download CA bundle
  if [ -d ../openssl ]; then
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

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives lib/*.a

  ../_peclean.py "${_ref}" src/*.exe
  ../_peclean.py "${_ref}" lib/*.dll

  ../_sign-code.sh "${_ref}" src/*.exe
  ../_sign-code.sh "${_ref}" lib/*.dll

  touch -c -r "${_ref}" src/*.exe
  touch -c -r "${_ref}" lib/*.dll
  touch -c -r "${_ref}" lib/*.def
  touch -c -r "${_ref}" lib/*.a

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" src/*.map
    touch -c -r "${_ref}" lib/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers src/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers lib/*.dll | grep -a -E -i "(file format|dll name)"

  ${_WINE} src/curl.exe --version | tee "curl-${_CPU}.txt"
  ${_WINE} src/curl.exe --dump-module-paths

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
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
  cp -f -p docs/*.md                "${_DST}/docs/"
  cp -f -p include/curl/*.h         "${_DST}/include/curl/"
  cp -f -p src/*.exe                "${_DST}/bin/"
  cp -f -p lib/*.dll                "${_DST}/bin/"
  cp -f -p lib/*.def                "${_DST}/bin/"
  cp -f -p lib/*.a                  "${_DST}/lib/"
  cp -f -p CHANGES                  "${_DST}/CHANGES.txt"
  cp -f -p COPYING                  "${_DST}/COPYING.txt"
  cp -f -p README                   "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES            "${_DST}/RELEASE-NOTES.txt"

  if [ -d ../openssl ]; then
    cp -f -p lib/mk-ca-bundle.pl  "${_DST}/"
    cp -f -p ../ca-bundle.crt     "${_DST}/bin/curl-ca-bundle.crt"
    [ -f ../openssl/LICENSE.txt ] && cp -f -p ../openssl/LICENSE.txt "${_DST}/COPYING-openssl.txt"
  fi

  [ -d ../zlibng ]  && cp -f -p ../zlibng/LICENSE.md "${_DST}/COPYING-zlib-ng.md"
  [ -d ../zlib ]    && cp -f -p ../zlib/README       "${_DST}/COPYING-zlib.txt"
  [ -d ../brotli ]  && cp -f -p ../brotli/LICENSE    "${_DST}/COPYING-brotli.txt"
  [ -d ../libssh2 ] && cp -f -p ../libssh2/COPYING   "${_DST}/COPYING-libssh2.txt"
  [ -d ../nghttp2 ] && cp -f -p ../nghttp2/COPYING   "${_DST}/COPYING-nghttp2.txt"
  [ -d ../nghttp3 ] && cp -f -p ../nghttp3/COPYING   "${_DST}/COPYING-nghttp3.txt"
  [ -d ../ngtcp2 ]  && cp -f -p ../ngtcp2/COPYING    "${_DST}/COPYING-ngtcp2.txt"
  [ -d ../libidn2 ] && cp -f -p ../libidn2/COPYING   "${_DST}/COPYING-libidn2.txt"

  if [ "${_BRANCH#*main*}" = "${_BRANCH}" ]; then
    cp -f -p src/*.map                "${_DST}/bin/"
    cp -f -p lib/*.map                "${_DST}/bin/"
  fi

  ../_pkg.sh "$(pwd)/${_ref}"
)
