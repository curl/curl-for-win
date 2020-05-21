#!/bin/sh -ex

# Copyright 2014-2020 Viktor Szakats <https://vsz.me/>
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

  # Detect host OS
  case "$(uname)" in
    *_NT*)   os='win';;
    Linux*)  os='linux';;
    Darwin*) os='mac';;
    *BSD)    os='bsd';;
  esac

  # Prepare build

  find . -name '*.dll' -type f -delete
  find . -name '*.def' -type f -delete

  if [ ! -f 'Makefile' ]; then
    if [ "${os}" = 'win' ]; then
      # FIXME: This will not create a fully release-compliant file tree,
      #        e.g. documentation will be incomplete.
      ./buildconf.bat
    else
      # FIXME: Replace this with `./buildconf` call
      cp -f -p Makefile.dist Makefile
    fi
  fi

  # Build

  options='mingw32-ipv6-sspi-ldaps-srp'

  export ARCH="w${_cpu}"
  # Use -DCURL_STATICLIB when compiling libcurl. This option prevents
  # public libcurl functions being marked as 'exported'. It is useful to
  # avoid the chance of libcurl functions getting exported from final
  # binaries when linked against static libcurl lib.
  # TODO:
  #   Enable UNICODE builds: -DUNICODE -D_UNICODE
  #   Enable: -DHAVE_ATOMIC
  #      Ref: https://github.com/curl/curl/pull/5017
  export CURL_CFLAG_EXTRAS='-DCURL_STATICLIB -DCURL_ENABLE_MQTT -fno-ident'
  [ "${_cpu}" = '32' ] && CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -fno-asynchronous-unwind-tables"
  export CURL_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
  export CURL_LDFLAG_EXTRAS_EXE
  export CURL_LDFLAG_EXTRAS_DLL
  if [ "${_cpu}" = '32' ]; then
    CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,_mainCRTStartup'
  else
    CURL_LDFLAG_EXTRAS_EXE='-Wl,--pic-executable,-e,mainCRTStartup'
    CURL_LDFLAG_EXTRAS_DLL='-Wl,--image-base,0x150000000'
    CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--high-entropy-va"
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
  grep -a -h '^CURL_EXTERN ' include/curl/*.h \
  | sed 's/CURL_EXTERN \([a-zA-Z_\* ]*\)[\* ]\([a-z_]*\)(\(.*\)$/\2/g' \
  | grep -a -v '^$' \
  | sort | tee -a libcurl.def
  CURL_LDFLAG_EXTRAS_DLL="${CURL_LDFLAG_EXTRAS_DLL} ../libcurl.def"

  export ZLIB_PATH=../../zlib/pkg/usr/local
  options="${options}-zlib"
  if [ -d ../brotli ]; then
    options="${options}-brotli"
    export BROTLI_PATH=../../brotli/pkg/usr/local
    export BROTLI_LIBS='-Wl,-Bstatic -lbrotlidec-static -lbrotlicommon-static -Wl,-Bdynamic'
  fi

  [ -d ../openssl ] && export OPENSSL_PATH=../../openssl
  if [ -n "${OPENSSL_PATH}" ]; then
    CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG"
    options="${options}-ssl"
    export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
    export OPENSSL_LIBPATH="${OPENSSL_PATH}"
    export OPENSSL_LIBS='-lssl -lcrypto'
  fi
  options="${options}-winssl"
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
    export LIBCARES_PATH=../../c-ares/pkg/usr/local
  fi
  if [ -d ../libidn2 ]; then
    options="${options}-idn2"
    export LIBIDN2_PATH=../../libidn2/pkg/usr/local
  else
    options="${options}-winidn"
  fi

  if [ "${_cpu}" = '64' ]; then
    export CURL_DLL_SUFFIX=-x64
  fi
  export CURL_DLL_A_SUFFIX=.dll

  # Make sure to link zlib (and only zlib) in static mode when building
  # `libcurl.dll`, so that it wouldn't depend on a `zlib1.dll`.
  # In some build environments (such as MSYS2), `libz.dll.a` is also offered
  # along with `libz.a` causing the linker to pick up the shared library.
  export DLL_LIBS='-Wl,-Bstatic -lz -Wl,-Bdynamic'

  # Link libssh2 to libcurl in static mode as well.
  # Use a hack: Delete the implib
  rm -f "../libssh2/win32/libssh2.dll.a"

  export CROSSPREFIX="${_CCPREFIX}"

  if [ "${CC}" = 'mingw-clang' ]; then
    export CURL_CC="clang${_CCSUFFIX}"
    if [ "${os}" != 'win' ]; then
      CURL_CFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${CURL_CFLAG_EXTRAS}"
      [ "${os}" = 'linux' ] && CURL_LDFLAG_EXTRAS="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${CURL_LDFLAG_EXTRAS}"
      CURL_LDFLAG_EXTRAS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${CURL_LDFLAG_EXTRAS}"
    fi
  fi

  ${_MAKE} -j 2 mingw32-clean
  ${_MAKE} -j 2 "${options}"

  # Download CA bundle
  [ -f '../ca-bundle.crt' ] || \
    curl -R --xattr -fsS -o '../ca-bundle.crt' 'https://curl.haxx.se/ca/cacert.pem'

  openssl dgst -sha256 '../ca-bundle.crt'
  openssl dgst -sha512 '../ca-bundle.crt'

  # Make steps for determinism

  readonly _ref='CHANGES'

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g lib/*.a

  ../_peclean.py "${_ref}" src/*.exe
  ../_peclean.py "${_ref}" lib/*.dll

  ../_sign.sh "${_ref}" src/*.exe
  ../_sign.sh "${_ref}" lib/*.dll

  touch -c -r "${_ref}" src/*.exe
  touch -c -r "${_ref}" lib/*.dll
  touch -c -r "${_ref}" lib/*.a

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    touch -c -r "${_ref}" src/*.map
    touch -c -r "${_ref}" lib/*.map
    touch -c -r "${_ref}" lib/*.def
  fi

  # Tests

  "${_CCPREFIX}objdump" -x src/*.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" -x lib/*.dll | grep -a -E -i "(file format|dll name)"

  ${_WINE} src/curl.exe -V

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  [ -d ../brotli ] || _BAS="${_BAS}-nobrotli"
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
  cp -f -p lib/*.a                  "${_DST}/lib/"
  cp -f -p lib/mk-ca-bundle.pl      "${_DST}/"
  cp -f -p CHANGES                  "${_DST}/CHANGES.txt"
  cp -f -p COPYING                  "${_DST}/COPYING.txt"
  cp -f -p README                   "${_DST}/README.txt"
  cp -f -p RELEASE-NOTES            "${_DST}/RELEASE-NOTES.txt"
  cp -f -p ../ca-bundle.crt         "${_DST}/bin/curl-ca-bundle.crt"

  [ -d ../zlib ]     && cp -f -p ../zlib/README     "${_DST}/COPYING-zlib.txt"
  [ -d ../brotli ]   && cp -f -p ../brotli/LICENSE  "${_DST}/COPYING-brotli.txt"
  [ -d ../libssh2 ]  && cp -f -p ../libssh2/COPYING "${_DST}/COPYING-libssh2.txt"
  [ -d ../nghttp2 ]  && cp -f -p ../nghttp2/COPYING "${_DST}/COPYING-nghttp2.txt"
  [ -d ../libidn2 ]  && cp -f -p ../libidn2/COPYING "${_DST}/COPYING-libidn2.txt"
  [ -d ../openssl ]  && cp -f -p ../openssl/LICENSE "${_DST}/LICENSE-openssl.txt"

  if [ "${_BRANCH#*master*}" = "${_BRANCH}" ]; then
    cp -f -p src/*.map                "${_DST}/bin/"
    cp -f -p lib/*.map                "${_DST}/bin/"
    cp -f -p lib/*.def                "${_DST}/bin/"
  fi

  unix2dos -q -k "${_DST}"/*.txt
  unix2dos -q -k "${_DST}"/docs/*.md
  unix2dos -q -k "${_DST}"/docs/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
