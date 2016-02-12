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
_CPU="$2"

(
   cd "${_NAM}" || exit

   # Build

   export ZLIB_PATH=../../zlib
   [ -d ../libressl ] && export OPENSSL_PATH=../../libressl
   [ -d ../openssl ]  && export OPENSSL_PATH=../../openssl
   export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
   export OPENSSL_LIBPATH="${OPENSSL_PATH}"
   export OPENSSL_LIBS='-lssl -lcrypto'
   export NGHTTP2_PATH=../../nghttp2
   export LIBRTMP_PATH=../../librtmp
   export LIBSSH2_PATH=../../libssh2
   export ARCH="w${_CPU}"
   export CURL_CFLAG_EXTRAS='-DCURL_STATICLIB -DNGHTTP2_STATICLIB -fno-ident'
   export CURL_LDFLAG_EXTRAS='-static-libgcc'

   # TOFIX: This will not create a fully release-comliant file tree,
   #        f.e. documentation will be incomplete.
   [ -f 'Makefile' ] || ./buildconf.bat

   OPTIONS='mingw32-ssh2-ssl-sspi-zlib-ldaps-srp-nghttp2-ipv6'
   [ -d ../librtmp ] && OPTIONS="${OPTIONS}-rtmp"
   # Do not link WinIDN in 32-bit builds, for Windows XP compatibility (missing normaliz.dll)
   [ "${_CPU}" = '64' ] && OPTIONS="${OPTIONS}-winidn"
   mingw32-make mingw32-clean
   mingw32-make "${OPTIONS}"

   # Download CA bundle
   [ -f '../ca-bundle.crt' ] || \
      curl -R -fsS -o '../ca-bundle.crt' 'https://curl.haxx.se/ca/cacert.pem'

   # Make steps for determinism

   readonly _REF='CHANGES'

   strip -p --enable-deterministic-archives -g lib/*.a

   ../_peclean.py "${_REF}" 'src/*.exe'
   ../_peclean.py "${_REF}" 'lib/*.dll'

   touch -c -r "${_REF}" ../ca-bundle.crt
   touch -c -r "${_REF}" src/*.exe
   touch -c -r "${_REF}" lib/*.dll
   touch -c -r "${_REF}" lib/*.a

   # Test run

   src/curl.exe --version

   # Create package

   [ -d ../libressl ] && _BAS="${_NAM}-${_VER}-win${_CPU}-mingw-libressl"
   [ -d ../openssl ]  && _BAS="${_NAM}-${_VER}-win${_CPU}-mingw"
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
#  cp -f -p ../librtmp/COPYING       "${_DST}/COPYING-librtmp.txt"
   cp -f -p ../nghttp2/COPYING       "${_DST}/COPYING-nghttp2.txt"

   [ -d ../libressl ] && cp -f -p ../libressl/COPYING "${_DST}/COPYING-libressl.txt"
   [ -d ../openssl ]  && cp -f -p ../openssl/LICENSE  "${_DST}/LICENSE-openssl.txt"

   unix2dos -k "${_DST}"/*.txt
   unix2dos -k "${_DST}"/docs/*.md
   unix2dos -k "${_DST}"/docs/*.txt

   ../_pack.sh "$(pwd)/${_REF}"
   ../_ul.sh
)
