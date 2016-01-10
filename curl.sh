#!/bin/sh -x

# Copyright 2014-2016 Viktor Szakats <https://github.com/vszakats>
# See LICENSE.md

export _NAM
export _VER
export _CPU
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
   export OPENSSL_PATH=../../openssl
   export OPENSSL_INCLUDE="${OPENSSL_PATH}/include"
   export OPENSSL_LIBPATH="${OPENSSL_PATH}"
   export OPENSSL_LIBS='-lssl -lcrypto'
   export NGHTTP2_PATH=../../nghttp2
   export LIBRTMP_PATH=../../librtmp
   export LIBSSH2_PATH=../../libssh2
   [ "${_CPU}" = 'win32' ] && export ARCH=w32
   [ "${_CPU}" = 'win64' ] && export ARCH=w64
   export CURL_CFLAG_EXTRAS='-DCURL_STATICLIB -DNGHTTP2_STATICLIB -fno-ident'
   export CURL_LDFLAG_EXTRAS='-static-libgcc'

   [ -f 'Makefile' ] || ./buildconf.bat

   mingw32-make mingw32-clean
   # - '-rtmp' is not enabled because libcurl then (of course) needs librtmp
   #   even if its functionality is not actually needed or used
   # - Do not link WinIDN in 32-bit builds, for Windows XP compatibility (missing normaliz.dll)
   [ "${_CPU}" = 'win32' ] && mingw32-make mingw32-ssh2-ssl-sspi-zlib-ldaps-srp-nghttp2-ipv6
   [ "${_CPU}" = 'win64' ] && mingw32-make mingw32-ssh2-ssl-sspi-zlib-ldaps-srp-nghttp2-ipv6-winidn

   # Download CA bundle
   [ -f '../ca-bundle.crt' ] || curl -R -fsS \
      -o '../ca-bundle.crt' \
      -L --proto-redir =https 'https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt'

   # Make steps for determinism

   if ls lib/*.a   > /dev/null 2>&1 ; then strip -p --enable-deterministic-archives -g lib/*.a   ; fi
   if ls lib/*.lib > /dev/null 2>&1 ; then strip -p --enable-deterministic-archives -g lib/*.lib ; fi

   python ../_peclean.py 'src/*.exe'
   python ../_peclean.py 'lib/*.dll'

   touch -c src/*.exe        -r CHANGES
   touch -c lib/*.dll        -r CHANGES
   touch -c ../ca-bundle.crt -r CHANGES
   touch -c lib/*.a          -r CHANGES
   touch -c lib/*.lib        -r CHANGES

   # Test run

   src/curl.exe --version

   # Create package

   _BAS="${_NAM}-${_VER}-${_CPU}-mingw"
   _DST="$(mktemp -d)/${_BAS}"

   mkdir -p "${_DST}/docs/libcurl/opts"
   mkdir -p "${_DST}/include/curl"
   mkdir -p "${_DST}/lib"
   mkdir -p "${_DST}/bin"

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
   cp -f -p docs/libcurl/opts/*.html "${_DST}/docs/libcurl/opts/"
   cp -f -p docs/libcurl/*.html      "${_DST}/docs/libcurl/"
   cp -f -p docs/*.html              "${_DST}/docs/"
   cp -f -p docs/*.md                "${_DST}/docs/"
   cp -f -p include/curl/*.h         "${_DST}/include/curl/"
   cp -f -p src/*.exe                "${_DST}/bin/"
   cp -f -p lib/*.dll                "${_DST}/bin/"
   cp -f -p lib/mk-ca-bundle.pl      "${_DST}/"
   cp -f -p CHANGES                  "${_DST}/CHANGES.txt"
   cp -f -p COPYING                  "${_DST}/COPYING.txt"
   cp -f -p README                   "${_DST}/README.txt"
   cp -f -p RELEASE-NOTES            "${_DST}/RELEASE-NOTES.txt"
   cp -f -p ../ca-bundle.crt         "${_DST}/bin/curl-ca-bundle.crt"

   cp -f -p ../openssl/LICENSE       "${_DST}/LICENSE-openssl.txt"
   cp -f -p ../libssh2/COPYING       "${_DST}/COPYING-libssh2.txt"
#  cp -f -p ../librtmp/COPYING       "${_DST}/COPYING-librtmp.txt"
   cp -f -p ../nghttp2/COPYING       "${_DST}/COPYING-nghttp2.txt"

   if ls lib/*.a   > /dev/null 2>&1 ; then cp -f -p lib/*.a   "${_DST}/lib" ; fi
   if ls lib/*.lib > /dev/null 2>&1 ; then cp -f -p lib/*.lib "${_DST}/lib" ; fi

   unix2dos -k "${_DST}"/*.txt
   unix2dos -k "${_DST}"/docs/*.md
   unix2dos -k "${_DST}"/docs/*.txt

   touch -c "${_DST}/docs/examples"     -r CHANGES
   touch -c "${_DST}/docs/libcurl/opts" -r CHANGES
   touch -c "${_DST}/docs/libcurl"      -r CHANGES
   touch -c "${_DST}/docs"              -r CHANGES
   touch -c "${_DST}/include/curl"      -r CHANGES
   touch -c "${_DST}/include"           -r CHANGES
   touch -c "${_DST}/lib"               -r CHANGES
   touch -c "${_DST}/bin"               -r CHANGES
   touch -c "${_DST}"                   -r CHANGES

   ../_pack.sh "$(pwd)/CHANGES"
   ../_ul.sh
)
