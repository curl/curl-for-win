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
  cd "${_NAM}" || exit 0

  readonly _ref='CHANGES'

  # Build

  find . -name '*.o'   -type f -delete
  find . -name '*.a'   -type f -delete
  find . -name '*.pc'  -type f -delete
  find . -name '*.dll' -type f -delete
  find . -name '*.exe' -type f -delete

  engdir='engines'

  [ "${_cpu}" = '32' ] && options='mingw'
  [ "${_cpu}" = '64' ] && options='mingw64'
  if [ "${_BRANCH#*lto*}" != "${_BRANCH}" ]; then
    # Create a fixed seed based on the timestamp of the OpenSSL source package.
    options="${options} -flto -ffat-lto-objects -frandom-seed=$(stat -c %Y "${_ref}")"
    # mingw64 build (as of mingw 5.2.0) will fail without the `no-asm` option.
    [ "${_cpu}" = '64' ] && options="${options} no-asm"
  fi
  if [ "$(echo "${OPENSSL_VER_}" | cut -c -5)" = '1.0.2' ]; then
    [ "${_cpu}" = '32' ] && export SHARED_RCFLAGS='--target=pe-i386'
    [ "${_cpu}" = '64' ] && export SHARED_RCFLAGS='--target=pe-x86-64'
    options="${options} -m${_cpu} -static-libgcc no-rc5 no-ssl3"
  else
    options="${options} no-filenames"
  fi
  if [ "${_cpu}" = '64' ]; then
    options="${options} enable-ec_nistp_64_gcc_128"
    [ "${_CCVER}" -ge '0500' ] && options="${options} -Wl,--high-entropy-va -Wl,--image-base,0x151000000"
  fi
  [ "${_BRANCH#*extmingw*}" = "${_BRANCH}" ] && [ "${_cpu}" = '32' ] && options="${options} -fno-asynchronous-unwind-tables"

  # AR=, NM=, RANLIB=
  unset CC

  # shellcheck disable=SC2086
  ./Configure ${options} shared \
    "--cross-compile-prefix=${_CCPREFIX}" \
    -fno-ident \
    -Wl,--nxcompat -Wl,--dynamicbase \
    no-unit-test \
    no-idea \
    no-tests \
    '--prefix=/usr/local'
  [ "$(echo "${OPENSSL_VER_}" | cut -c -4)" = '1.1.' ] || make depend
  make

  # Make steps for determinism

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g ./*.a
  "${_CCPREFIX}strip" -p -s apps/openssl.exe
  "${_CCPREFIX}strip" -p -s apps/*.dll
  if ls ${engdir}/*.dll > /dev/null 2>&1; then
    "${_CCPREFIX}strip" -p -s ${engdir}/*.dll
  fi

  ../_peclean.py "${_ref}" 'apps/openssl.exe'
  ../_peclean.py "${_ref}" 'apps/*.dll'

  ../_sign.sh 'apps/openssl.exe'
  ../_sign.sh 'apps/*.dll'

  if ls ${engdir}/*.dll > /dev/null 2>&1; then
    ../_peclean.py "${_ref}" "${engdir}/*.dll"

    ../_sign.sh "${engdir}/*.dll"
  fi

  touch -c -r "${_ref}" apps/openssl.exe
  touch -c -r "${_ref}" apps/*.dll
  touch -c -r "${_ref}" include/openssl/*.h
  touch -c -r "${_ref}" ./*.a
  touch -c -r "${_ref}" ./*.pc
  if ls ${engdir}/*.dll > /dev/null 2>&1; then
    touch -c -r "${_ref}" ${engdir}/*.dll
  fi

  # Tests

  "${_CCPREFIX}objdump" -x apps/openssl.exe | grep -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" -x apps/*.dll       | grep -E -i "(file format|dll name)"

  ${_WINE} apps/openssl.exe version
  ${_WINE} apps/openssl.exe ciphers

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib/pkgconfig"

  if ls ${engdir}/*.dll > /dev/null 2>&1; then
    mkdir -p "${_DST}/${engdir}"
    cp -f -p ${engdir}/*.dll  "${_DST}/${engdir}/"
  fi

  cp -f -p apps/openssl.cnf    "${_DST}/"
  cp -f -p apps/openssl.exe    "${_DST}/"
  cp -f -p apps/*.dll          "${_DST}/"
  cp -f -p include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p ./*.a               "${_DST}/lib/"
  cp -f -p ./*.pc              "${_DST}/lib/pkgconfig/"
  cp -f -p CHANGES             "${_DST}/CHANGES.txt"
  cp -f -p LICENSE             "${_DST}/LICENSE.txt"
  cp -f -p README              "${_DST}/README.txt"
  cp -f -p FAQ                 "${_DST}/FAQ.txt"
  cp -f -p NEWS                "${_DST}/NEWS.txt"

  # Luckily, applink is not implemented for 64-bit mingw, omit this file then
  [ "${_cpu}" = '32' ] && cp -f -p ms/applink.c "${_DST}/include/openssl/"

  unix2dos -k "${_DST}"/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
