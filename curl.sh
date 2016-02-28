#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
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

   # Build

   export ZLIB_PATH=../../zlib
   [ -d ../libressl ] && export OPENSSL_PATH=../../libressl
   [ -d ../openssl ]  && export OPENSSL_PATH=../../openssl
   export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
   export OPENSSL_LIBPATH="${OPENSSL_PATH}"
   export OPENSSL_LIBS='-lssl -lcrypto'
   export NGHTTP2_PATH=../../nghttp2/pkg/usr/local
   export LIBIDN_PATH=../../libidn/pkg/usr/local
   export LIBCARES_PATH=../../c-ares
   export LIBRTMP_PATH=../../librtmp
   export LIBSSH2_PATH=../../libssh2
   export ARCH="w${_cpu}"
   export CURL_CFLAG_EXTRAS='-DCURL_STATICLIB -DNGHTTP2_STATICLIB -fno-ident'
   export CURL_LDFLAG_EXTRAS='-static-libgcc -Wl,--nxcompat -Wl,--dynamicbase'
   [ "${_cpu}" = '32' ] && CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--pic-executable,-e,_mainCRTStartup"
   [ "${_cpu}" = '64' ] && CURL_LDFLAG_EXTRAS="${CURL_LDFLAG_EXTRAS} -Wl,--pic-executable,-e,mainCRTStartup -Wl,--high-entropy-va -Wl,--image-base,0x150000000"

   export CROSSPREFIX="${_CCPREFIX}"

   # TOFIX: This will not create a fully release-compliant file tree,
   #        f.e. documentation will be incomplete.
   [ -f 'Makefile' ] || ./buildconf.bat

   options='mingw32-ssh2-ssl-sspi-zlib-ldaps-srp-nghttp2-ipv6'
   [ -d ../c-ares ] && options="${options}-ares"
   [ -d ../librtmp ] && options="${options}-rtmp"
   if [ -d ../libidn ] ; then
      options="${options}-idn"
      CURL_CFLAG_EXTRAS="${CURL_CFLAG_EXTRAS} -DHAVE_IDN_FREE_H"
   else
      # NOTE: If Windows XP is missing `normaliz.dll`, install this package:
      #       https://www.microsoft.com/en-us/download/details.aspx?id=734
      options="${options}-winidn"
   fi
   mingw32-make mingw32-clean
   mingw32-make "${options}"

   # Download CA bundle
   [ -f '../ca-bundle.crt' ] || \
      curl -R -fsS -o '../ca-bundle.crt' 'https://curl.haxx.se/ca/cacert.pem'

   # Make steps for determinism

   readonly _ref='CHANGES'

   strip -p --enable-deterministic-archives -g lib/*.a

   ../_peclean.py "${_ref}" 'src/*.exe'
   ../_peclean.py "${_ref}" 'lib/*.dll'

   touch -c -r "${_ref}" ../ca-bundle.crt
   touch -c -r "${_ref}" src/*.exe
   touch -c -r "${_ref}" lib/*.dll
   touch -c -r "${_ref}" lib/*.a

   # Tests

   src/curl.exe -V

   objdump -x src/*.exe | grep -E -i "(file format|dll name)"
   objdump -x lib/*.dll | grep -E -i "(file format|dll name)"

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
      for file in docs/* ; do
         if [ -f "${file}" ] && echo "${file}" | grep -v '\.' > /dev/null 2>&1 ; then
            cp -f -p "${file}" "${_DST}/${file}.txt"
         fi
      done
      for file in docs/libcurl/* ; do
         if [ -f "${file}" ] && echo "${file}" | grep -v '\.' > /dev/null 2>&1 ; then
            cp -f -p "${file}" "${_DST}/${file}.txt"
         fi
      done
   )
   cp -f -p docs/libcurl/opts/*.html "${_DST}/docs/libcurl/opts/"
   cp -f -p docs/libcurl/*.html      "${_DST}/docs/libcurl/"
   cp -f -p docs/*.html              "${_DST}/docs/"
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

   cp -f -p ../libssh2/COPYING       "${_DST}/COPYING-libssh2.txt"
   cp -f -p ../nghttp2/COPYING       "${_DST}/COPYING-nghttp2.txt"

   [ -d ../libidn ]   && cp -f -p ../libidn/COPYING   "${_DST}/COPYING-libidn.txt"
   [ -d ../librtmp ]  && cp -f -p ../librtmp/COPYING  "${_DST}/COPYING-librtmp.txt"
   [ -d ../libressl ] && cp -f -p ../libressl/COPYING "${_DST}/COPYING-libressl.txt"
   [ -d ../openssl ]  && cp -f -p ../openssl/LICENSE  "${_DST}/LICENSE-openssl.txt"

   unix2dos -k "${_DST}"/*.txt
   unix2dos -k "${_DST}"/docs/*.md
   unix2dos -k "${_DST}"/docs/*.txt

   ../_pack.sh "$(pwd)/${_ref}"
   ../_ul.sh
)
