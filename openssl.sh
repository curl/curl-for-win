#!/bin/sh -ex

# Copyright 2014-present Viktor Szakats <https://vsz.me/>
# See LICENSE.md

export _NAM
export _VER
export _OUT
export _BAS
export _DST

_NAM="$(basename "$0")"
_NAM="$(echo "${_NAM}" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  if [ "${_OS}" = 'win' ]; then
    # Required on MSYS2 for pod2man and pod2html in 'make install' phase
    export PATH="${PATH}:/usr/bin/core_perl"
  fi

  if [ -f 'CHANGES.md' ]; then
    # OpenSSL 3.x
    readonly _ref='CHANGES.md'
  else
    readonly _ref='CHANGES'
  fi

  case "${_OS}" in
    bsd|mac) unixts="$(TZ=UTC stat -f '%m' "${_ref}")";;
    *)       unixts="$(TZ=UTC stat --format '%Y' "${_ref}")";;
  esac

  # Build

  rm -r -f pkg

  find . -name '*.o'   -delete
  find . -name '*.obj' -delete
  find . -name '*.a'   -delete
  find . -name '*.pc'  -delete
  find . -name '*.def' -delete
  find . -name '*.dll' -delete
  find . -name '*.exe' -delete
  find . -name '*.tmp' -delete

  [ "${_CPU}" = 'x86' ] && options='mingw'
  [ "${_CPU}" = 'x64' ] && options='mingw64'
  if [ "${_BRANCH#*lto*}" != "${_BRANCH}" ]; then
    # Create a fixed seed based on the timestamp of the OpenSSL source package.
    options="${options} -flto -ffat-lto-objects -frandom-seed=${unixts}"
    # mingw64 build (as of mingw 5.2.0) will fail without the `no-asm` option.
    [ "${_CPU}" = 'x64' ] && options="${options} no-asm"
  fi
  options="${options} no-filenames"
  [ "${_CPU}" = 'x64' ] && options="${options} enable-ec_nistp_64_gcc_128 -Wl,--high-entropy-va -Wl,--image-base,0x151000000"
  [ "${_CPU}" = 'x86' ] && options="${options} -fno-asynchronous-unwind-tables"

  if [ -f 'CHANGES.md' ] && [ "${CC}" = 'mingw-clang' ]; then
    # OpenSSL 3.x
    # To avoid warnings when passing C compiler options to the linker
    options="${options} -Wno-unused-command-line-argument"
    export CC=clang
    if [ "${_OS}" != 'win' ]; then
      export options="${options} --target=${_TRIPLET} --sysroot=${_SYSROOT}"
      [ "${_OS}" = 'linux' ] && options="-L$(find "/usr/lib/gcc/${_TRIPLET}" -name '*posix' | head -n 1) ${options}"
    # export LDFLAGS="-target ${_TRIPLET} --sysroot ${_SYSROOT} ${LDFLAGS}"
    fi
    export AR=${_CCPREFIX}ar
    export NM=${_CCPREFIX}nm
    export RANLIB=${_CCPREFIX}ranlib
    export RC=${_CCPREFIX}windres
    _CONF_CCPREFIX=
  else
    unset CC
    _CONF_CCPREFIX="${_CCPREFIX}"
  fi

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
  if [ -f 'CHANGES.md' ]; then
    # OpenSSL 3.x
    _ssldir="ssl"
    _lib='/lib'
    [ "${_CPU}" = 'x64' ] && _lib='/lib64'
  else
    _ssldir="${_prefix}/ssl"
    _lib='/lib'
  fi
  _pkr='pkg'

  # shellcheck disable=SC2086
  ./Configure-patched ${options} shared \
    "--cross-compile-prefix=${_CONF_CCPREFIX}" \
    -fno-ident \
    -Wl,--nxcompat -Wl,--dynamicbase \
    no-unit-test \
    no-idea no-legacy \
    no-tests \
    no-makedepend \
    "--prefix=${_prefix}" \
    "--openssldir=${_ssldir}"
  SOURCE_DATE_EPOCH=${unixts} TZ=UTC make --jobs 2
  # Install it so that it can be detected by CMake
  # (ending slash required)
  make --jobs 2 install "DESTDIR=$(pwd)/${_pkr}/" >/dev/null # 2>&1

  # DESTDIR= + --prefix=
  # OpenSSL 1.1.1d and newer strips the drive letter.
  # OpenSSL 3.x does not. (openssl/pkg/C:/Windows/System32/OpenSSL)
  if [ -f 'CHANGES.md' ]; then
    _pkg="${_pkr}/${_prefix}"
    _pks="${_pkr}/${_prefix}/${_ssldir}"
  else
    _pkg="${_pkr}/$(echo "${_prefix}" | sed 's|[a-zA-Z]:/||')"
    _pks="${_pkr}/$(echo "${_ssldir}" | sed 's|[a-zA-Z]:/||')"
  fi

  # Make steps for determinism

  "${_CCPREFIX}strip" --preserve-dates --strip-debug --enable-deterministic-archives "${_pkg}${_lib}"/*.a
  "${_CCPREFIX}strip" --preserve-dates --strip-all "${_pkg}"/bin/openssl.exe
  "${_CCPREFIX}strip" --preserve-dates --strip-all "${_pkg}"/bin/*.dll
  if ls "${_pkg}${_lib}"/ossl-modules/*.dll >/dev/null 2>&1; then
    "${_CCPREFIX}strip" --preserve-dates --strip-all "${_pkg}${_lib}"/ossl-modules/*.dll
  fi
  if ls "${_pkg}${_lib}"/engines*/*.dll >/dev/null 2>&1; then
    "${_CCPREFIX}strip" --preserve-dates --strip-all "${_pkg}${_lib}"/engines*/*.dll
  fi

  ../_peclean.py "${_ref}" "${_pkg}"/bin/openssl.exe
  ../_peclean.py "${_ref}" "${_pkg}"/bin/*.dll

  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/openssl.exe
  ../_sign-code.sh "${_ref}" "${_pkg}"/bin/*.dll

  if ls "${_pkg}${_lib}"/ossl-modules/*.dll >/dev/null 2>&1; then
    ../_peclean.py "${_ref}" "${_pkg}${_lib}"/ossl-modules/*.dll

    ../_sign-code.sh "${_ref}" "${_pkg}${_lib}"/ossl-modules/*.dll
  fi
  if ls "${_pkg}${_lib}"/engines*/*.dll >/dev/null 2>&1; then
    ../_peclean.py "${_ref}" "${_pkg}${_lib}"/engines*/*.dll

    ../_sign-code.sh "${_ref}" "${_pkg}${_lib}"/engines*/*.dll
  fi

  touch -c -r "${_ref}" "${_pks}"/ct_log_list.cnf
  touch -c -r "${_ref}" "${_pks}"/ct_log_list.cnf.dist
  touch -c -r "${_ref}" "${_pks}"/openssl.cnf
  touch -c -r "${_ref}" "${_pks}"/openssl.cnf.dist
  touch -c -r "${_ref}" "${_pkg}"/bin/openssl.exe
  touch -c -r "${_ref}" "${_pkg}"/bin/*.dll
  touch -c -r "${_ref}" "${_pkg}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_pkg}${_lib}"/*.a
  touch -c -r "${_ref}" "${_pkg}${_lib}"/pkgconfig/*.pc
  if ls "${_pkg}${_lib}"/ossl-modules/*.dll >/dev/null 2>&1; then
    touch -c -r "${_ref}" "${_pkg}${_lib}"/ossl-modules/*
  fi
  if ls "${_pkg}${_lib}"/engines*/*.dll >/dev/null 2>&1; then
    touch -c -r "${_ref}" "${_pkg}${_lib}"/engines*/*
  fi

  # Tests

  "${_CCPREFIX}objdump" --all-headers "${_pkg}"/bin/openssl.exe | grep -a -E -i "(file format|dll name)"
  "${_CCPREFIX}objdump" --all-headers "${_pkg}"/bin/*.dll       | grep -a -E -i "(file format|dll name)"

  ${_WINE} "${_pkg}"/bin/openssl.exe version -a
  ${_WINE} "${_pkg}"/bin/openssl.exe ciphers -s -V -stdname

  # Create package

  _OUT="${_NAM}-${_VER}${_REV}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}"

  cp -f -p    "${_pks}"/ct_log_list.cnf      "${_DST}/"
  cp -f -p    "${_pks}"/ct_log_list.cnf.dist "${_DST}/"
  cp -f -p    "${_pks}"/openssl.cnf          "${_DST}/"
  cp -f -p    "${_pks}"/openssl.cnf.dist     "${_DST}/"
  cp -f -p    "${_pkg}"/bin/openssl.exe      "${_DST}/"
  cp -f -p    "${_pkg}"/bin/*.dll            "${_DST}/"
  cp -f -p -r "${_pkg}"/include              "${_DST}/"
  if [ -f 'CHANGES.md' ]; then
    # OpenSSL 3.x

    cp -f -p -r "${_pkg}${_lib}" "${_DST}/"

    cp -f -p CHANGES.md  "${_DST}/"
    cp -f -p LICENSE.txt "${_DST}/"
    cp -f -p README.md   "${_DST}/"
    cp -f -p FAQ.md      "${_DST}/"
    cp -f -p NEWS.md     "${_DST}/"
  else
    if ls "${_pkg}${_lib}"/engines*/*.dll >/dev/null 2>&1; then
      cp -f -p -r "${_pkg}${_lib}"/engines* "${_DST}/"
    fi

    mkdir -p "${_DST}/lib/pkgconfig"

    cp -f -p "${_pkg}${_lib}"/*.a            "${_DST}/lib/"
    cp -f -p "${_pkg}${_lib}"/pkgconfig/*.pc "${_DST}/lib/pkgconfig/"

    cp -f -p CHANGES     "${_DST}/CHANGES.txt"
    cp -f -p LICENSE     "${_DST}/LICENSE.txt"
    cp -f -p README      "${_DST}/README.txt"
    cp -f -p FAQ         "${_DST}/FAQ.txt"
    cp -f -p NEWS        "${_DST}/NEWS.txt"
  fi

  # Luckily, applink is not implemented for 64-bit mingw, omit this file then
  [ "${_CPU}" = 'x86' ] && cp -f -p ms/applink.c "${_DST}/include/openssl/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
