#!/bin/sh -ex

# Copyright 2014-2017 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"
_cpu="$2"

(
  cd "${_NAM}" || exit

  # Prepare build

  # TOFIX: This will not create a fully release-compliant file tree,
  #        f.e. documentation will be incomplete.
  [ -f 'Makefile' ] || ./buildconf.bat

  # Build

  options='mingw32-ipv6-sspi-ldaps-srp'

  export ARCH="w${_cpu}"
  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # public libcurl functions being marked as 'exported'. It's useful to
  # avoid the chance of libcurl functions getting exported from final
  # binaries when linked against static libcurl lib.
  export CURL_CFLAG_EXTRAS='-DCURL_STATICLIB -fno-ident'
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"
  export CURL_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
  export CURL_LDFLAG_EXTRAS_EXE
  export CURL_LDFLAG_EXTRAS_DLL
  if [ "${_cpu}" = '32' ]; then
    CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,_mainCRTStartup'
  else
    CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,mainCRTStartup'
    if [ "${_CCVER}" -ge '0500' ]; then
      CURL_LDFLAG_EXTRAS_DLL='-Wl,--image-base,0x150000000'
      CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--high-entropy-va"
    fi
  fi

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
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
  grep '^CURL_EXTERN ' include/curl/*.h \
  | awk 'match($0, /CURL_EXTERN ([a-zA-Z_\* ]*)[\* ]([a-z_]*)\(/, v) {print v[2]}' \
  | grep -v '^$' \
  | sort | tee -a libcurl.def
  CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} ../libcurl.def"

  export ZLIB_PATH=../../zlib
  options="${options}-zlib"

  [ -d ../libressl ] && export OPENSSL_PATH=../../libressl
  [ -d ../openssl ]  && export OPENSSL_PATH=../../openssl
  if [ -n "${OPENSSL_PATH}" ]; then
    options="${options}-ssl"
    export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
    export OPENSSL_LIBPATH="${OPENSSL_PATH}"
    export OPENSSL_LIBS='-lssl -lcrypto'
  else
    options="${options}-winssl"
  fi
  if [ -d ../libssh2 ]; then
    options="${options}-ssh2"
    export LIBSSH2_PATH=../../libssh2
  fi
  if [ -d ../nghttp2 ]; then
    options="${options}-nghttp2"
    export NGHTTP2_PATH=../../nghttp2/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DNGHTTP2_STATICLIB"
  fi
  if [ -d ../c-ares ]; then
    options="${options}-ares"
    export LIBCARES_PATH=../../c-ares
  fi
  if [ -d ../librtmp ]; then
    options="${options}-rtmp"
    export LIBRTMP_PATH=../../librtmp
  fi
  if [ -d ../libidn ]; then
    options="${options}-idn"
    export LIBIDN_PATH=../../libidn/pkg/usr/local
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_IDN_FREE_H"
  else
    options="${options}-winidn"
  fi

  # Make sure to link zlib (and only zlib) in static mode when building
  # `libcurl.dll`, so that it wouldn't depend on a `zlib1.dll`.
  # In some build environments (such as MSYS2), `libz.dll.a` is also offered
  # along with `libz.a` causing the linker to pick up the shared library.
  export DLL_LIBS='-Wl,-Bstatic -lz -Wl,-Bdynamic'

  export CROSSPREFIX="${_CCPREFIX}"

  ${_MAKE} mingw32-clean
  ${_MAKE} "${options}"

  # Download CA bundle
  [ -f '../ca-bundle.crt' ] || \
    curl -R -fsS -o '../ca-bundle.crt' 'https://curl.haxx.se/ca/cacert.pem'

  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g lib/*.a

  ../_peclean.py "${_ref}" 'src/*.exe'
  ../_peclean.py "${_ref}" 'lib/*.dll'

  ../_sign.sh 'src/*.exe'
  ../_sign.sh 'lib/*.dll'

  touch -c -r "${_ref}" ../ca-bundle.crt
  touch -c -r "${_ref}" src/*.exe
  touch -c -r "${_ref}" lib/*.dll
  touch -c -r "${_ref}" lib/*.a

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" src/*.map
    touch -c -r "${_ref}" lib/*.map
  fi

  # Tests

  "${_CCPREFIX}objdump" -x src/*.exe | grep -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" -x lib/*.dll | grep -E -i "(file format|dll name)"

  ${_WINE} src/curl.exe -V

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  [ -d ../libressl ] && _BAS="${_BAS}-libressl"
  [ -d ../librtmp ] && _BAS="${_BAS}-librtmp"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/docs/libcurl/opts"
  mkdir -p "${_DST}/include/curl"
  mkdir -p "${_DST}/lib"
  mkdir -p "${_DST}/bin"

  (
    set +x
    for file in docs/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -v '\.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
    for file in docs/libcurl/*; do
      if [ -f "${file}" ] && echo "${file}" | grep -q -v '\.'; then
        cp -f -p "${file}" "${_DST}/${file}.txt"
      fi
    done
  )
  cp -f -p docs/libcurl/*.html      "${_DST}/docs/libcurl/"
  cp -f -p docs/*.md                "${_DST}/docs/"
  cp -f -p include/curl/*.h         "${_DST}/include/curl/"
  cp -f -p src/*.exe                "${_DST}/bin/"
  cp -f -p lib/*.dll                "${_DST}/bin/"
  cp -f -p lib/*.a                  "${_DST}/lib/"
  cp -f -p lib/mk-ca-bundle.pl      "${_DST}/"
  cp -f -p CHANGES                  "${_DST}/CHANGES.txt"
  cp -f -p COPYING                  "${_DST}/COPYING.txt"
  cp -f -p README                   "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES            "${_DST}/RELEASE-NOTES.txt"
  cp -f -p ../ca-bundle.crt         "${_DST}/bin/curl-ca-bundle.crt"

  [ -d ../zlib ]     && cp -f -p ../zlib/README      "${_DST}/COPYING-zlib.txt"
  [ -d ../libssh2 ]  && cp -f -p ../libssh2/COPYING  "${_DST}/COPYING-libssh2.txt"
  [ -d ../nghttp2 ]  && cp -f -p ../nghttp2/COPYING  "${_DST}/COPYING-nghttp2.txt"
  [ -d ../libidn ]   && cp -f -p ../libidn/COPYING   "${_DST}/COPYING-libidn.txt"
  [ -d ../librtmp ]  && cp -f -p ../librtmp/COPYING  "${_DST}/COPYING-librtmp.txt"
  [ -d ../libressl ] && cp -f -p ../libressl/COPYING "${_DST}/COPYING-libressl.txt"
  [ -d ../openssl ]  && cp -f -p ../openssl/LICENSE  "${_DST}/LICENSE-openssl.txt"

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    cp -f -p src/*.map                "${_DST}/bin/"
    cp -f -p lib/*.map                "${_DST}/bin/"
  fi

  unix2dos -k "${_DST}"/*.txt
  unix2dos -k "${_DST}"/docs/*.md
  unix2dos -k "${_DST}"/docs/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
