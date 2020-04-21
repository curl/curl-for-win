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
  cd "${_NAM}" || exit 0

  # Detect host OS
  case "$(uname)" in
    *_NT*)   os='win';;
    Linux*)  os='linux';;
    Darwin*) os='mac';;
    *BSD)    os='bsd';;
  esac

  if [ "${os}" = 'win' ]; then
    # Required on MSYS2 for pod2man and pod2html in 'make install' phase
    export PATH="${PATH}:/usr/bin/core_perl"
  fi

  readonly _ref='CHANGES'

  case "${os}" in
    bsd|mac) unixts="$(TZ=UTC stat -f '%m' "${_ref}")";;
    *)       unixts="$(TZ=UTC stat -c '%Y' "${_ref}")";;
  esac

  # Build

  rm -fr pkg

  find . -name '*.o'   -type f -delete
  find . -name '*.a'   -type f -delete
  find . -name '*.pc'  -type f -delete
  find . -name '*.def' -type f -delete
  find . -name '*.dll' -type f -delete
  find . -name '*.exe' -type f -delete

  [ "${_cpu}" = '32' ] && options='mingw'
  [ "${_cpu}" = '64' ] && options='mingw64'
  if [ "${_BRANCH#*lto*}" != "${_BRANCH}" ]; then
    # Create a fixed seed based on the timestamp of the OpenSSL source package.
    options="${options} -flto -ffat-lto-objects -frandom-seed=${unixts}"
    # mingw64 build (as of mingw 5.2.0) will fail without the `no-asm` option.
    [ "${_cpu}" = '64' ] && options="${options} no-asm"
  fi
  options="${options} no-filenames"
  [ "${_cpu}" = '64' ] && options="${options} enable-ec_nistp_64_gcc_128 -Wl,--high-entropy-va -Wl,--image-base,0x151000000"
  [ "${_cpu}" = '32' ] && options="${options} -fno-asynchronous-unwind-tables"

  # AR=, NM=, RANLIB=
  unset CC

  # Patch OpenSSL ./Configure to make it accept Windows-style absolute
  # paths as --prefix. Without the patch it misidentifies all such
  # absolute paths as relative ones and aborts.
  # Reported: https://github.com/openssl/openssl/issues/9520
  sed 's|die "Directory given with --prefix|print "Directory given with --prefix|g' \
    < ./Configure > ./Configure-patched
  chmod a+x ./Configure-patched

  # Space or backslash not allowed. Needs to be a folder restricted
  # to Administrators across majority of Windows installations, versions
  # and configurations. We do avoid using the new default prefix set since
  # OpenSSL 1.1.1d, because by using the C:\Program Files*\ value, the
  # prefix remains vulnerable on localized Windows versions and for 32-bit
  # OpenSSL builds executed on 64-bit Windows systems. I believe that the
  # default below will give a "more secure" configuration for most Windows
  # installations. Also notice that said OpenSSL default breaks OpenSSL's
  # own build system when used in cross-build scenarios. The working patch
  # was submitted, but closed subsequently due to mixed/no response.
  # The secure solution would be to disable loading anything from hard-coded
  # disk locations, something that is not supported by OpenSSL at present.
  _prefix='C:/Windows/System32/OpenSSL'
  _pkr='pkg'

  # shellcheck disable=SC2086
  ./Configure-patched ${options} shared \
    "--cross-compile-prefix=${_CCPREFIX}" \
    -fno-ident \
    -Wl,--nxcompat -Wl,--dynamicbase \
    no-unit-test \
    no-idea \
    no-tests \
    no-makedepend \
    "--prefix=${_prefix}" \
    "--openssldir=${_prefix}/ssl"
  SOURCE_DATE_EPOCH=${unixts} TZ=UTC make -j 2
  # Install it so that it can be detected by CMake
  # (ending slash required)
  make -j 2 install "DESTDIR=$(pwd)/${_pkr}/" >/dev/null # 2>&1

  # DESTDIR= + --prefix= (OpenSSL 1.1.1d and newer strips the drive letter)
  _pkg="${_pkr}/$(echo "${_prefix}" | sed 's|[a-zA-Z]:/||')"
  _pks="${_pkr}/$(echo "${_prefix}" | sed 's|[a-zA-Z]:/||')/ssl"

  # Make steps for determinism

  "${_CCPREFIX}strip" -p --enable-deterministic-archives -g "${_pkg}"/lib/*.a
  "${_CCPREFIX}strip" -p -s "${_pkg}"/bin/openssl.exe
  "${_CCPREFIX}strip" -p -s "${_pkg}"/bin/*.dll
  if ls "${_pkg}"/lib/engines*/*.dll >/dev/null 2>&1; then
    "${_CCPREFIX}strip" -p -s "${_pkg}"/lib/engines*/*.dll
  fi

  ../_peclean.py "${_ref}" "${_pkg}"/bin/openssl.exe
  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.dll

  ../_sign.sh "${_ref}" "${_pkg}"/bin/openssl.exe
  ../_sign.sh "${_ref}" "${_pkg}"/bin/*.dll

  if ls "${_pkg}"/lib/engines*/*.dll >/dev/null 2>&1; then
    ../_peclean.py "${_ref}" "${_pkg}"/lib/engines*/*.dll

    ../_sign.sh "${_ref}" "${_pkg}"/lib/engines*/*.dll
  fi

  touch -c -r "${_ref}" "${_pks}"/ct_log_list.cnf
  touch -c -r "${_ref}" "${_pks}"/ct_log_list.cnf.dist
  touch -c -r "${_ref}" "${_pks}"/openssl.cnf
  touch -c -r "${_ref}" "${_pks}"/openssl.cnf.dist
  touch -c -r "${_ref}" "${_pkg}"/bin/openssl.exe
  touch -c -r "${_ref}" "${_pkg}"/bin/*.dll
  touch -c -r "${_ref}" "${_pkg}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a
  touch -c -r "${_ref}" "${_pkg}"/lib/pkgconfig/*.pc
  if ls "${_pkg}"/lib/engines*/*.dll >/dev/null 2>&1; then
    touch -c -r "${_ref}" "${_pkg}"/lib/engines*/*
  fi

  # Tests

  "${_CCPREFIX}objdump" -x "${_pkg}"/bin/openssl.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" -x "${_pkg}"/bin/*.dll       | grep -a -E -i "(file format|dll name)"

  ${_WINE} "${_pkg}"/bin/openssl.exe version
  ${_WINE} "${_pkg}"/bin/openssl.exe ciphers

  # Create package

  _BAS="${_NAM}-${_VER}-win${_cpu}-mingw"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib/pkgconfig"

  if ls "${_pkg}"/lib/engines*/*.dll >/dev/null 2>&1; then
    cp -f -p -r "${_pkg}"/lib/engines* "${_DST}/"
  fi

  cp -f -p "${_pks}"/ct_log_list.cnf      "${_DST}/"
  cp -f -p "${_pks}"/ct_log_list.cnf.dist "${_DST}/"
  cp -f -p "${_pks}"/openssl.cnf          "${_DST}/"
  cp -f -p "${_pks}"/openssl.cnf.dist     "${_DST}/"
  cp -f -p "${_pkg}"/bin/openssl.exe      "${_DST}/"
  cp -f -p "${_pkg}"/bin/*.dll            "${_DST}/"
  cp -f -p "${_pkg}"/include/openssl/*.h  "${_DST}/include/openssl/"
  cp -f -p "${_pkg}"/lib/*.a              "${_DST}/lib/"
  cp -f -p "${_pkg}"/lib/pkgconfig/*.pc   "${_DST}/lib/pkgconfig/"
  cp -f -p CHANGES                        "${_DST}/CHANGES.txt"
  cp -f -p LICENSE                        "${_DST}/LICENSE.txt"
  cp -f -p README                         "${_DST}/README.txt"
  cp -f -p FAQ                            "${_DST}/FAQ.txt"
  cp -f -p NEWS                           "${_DST}/NEWS.txt"

  # Luckily, applink is not implemented for 64-bit mingw, omit this file then
  [ "${_cpu}" = '32' ] && cp -f -p ms/applink.c "${_DST}/include/openssl/"

  unix2dos -q -k "${_DST}"/*.txt

  ../_pack.sh "$(pwd)/${_ref}"
  ../_ul.sh
)
