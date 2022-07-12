#!/bin/sh

# Copyright 2014-present Viktor Szakats. See LICENSE.md

# FIXME (upstream):
# - x64 mingw-w64 pthread ucrt static linking bug -> requires llvm-mingw
# - Building tests takes 3 minutes per target (on AppVeyor CI, at the time
#   of this writing) and consumes 9x the disk space for ${_BLDDIR}, that is
#   32MB -> 283MB (for x64).
#   Disabling them requires large edits in 3 CMakeList.txt files.
# - A test object named trampoline-x86_64.asm.obj ends up in libcrypto.a.
# - nasm includes the first 18 bytes of the HOME directory in its output.
#   e.g. rdrand-x86_64.asm.obj. This only affects libcrypto.a.
#   This is intentionally written into a '.file' record and --reproducible
#   does not disable it. See nasm/output/outcoff.c/coff_write_symbols()
#   PR: https://github.com/netwide-assembler/nasm/pull/33
#   binutils strip is able to delete it (llvm-strip is not, as of 14.0.6).
# - Objects built on different OSes result in a few byte differences.
#   e.g. windows.c.obj, a_utf8.c.obj. But not a_octet.c.obj.

# https://boringssl.googlesource.com/boringssl/
# https://bugs.chromium.org/p/boringssl/issues/list

# https://chromium.googlesource.com/chromium/src/third_party/boringssl/+/c9aca35314ba018fef141535ca9d4dd39d9bc688%5E%21/
# https://chromium.googlesource.com/chromium/src/third_party/boringssl/
# https://chromium.googlesource.com/chromium/src/+/refs/heads/main/DEPS
# https://github.com/chromium/chromium/commit/6a77772b9bacdf2490948f452bdbc34d3e871be1
# https://github.com/chromium/chromium/tree/main/third_party/boringssl
# https://raw.githubusercontent.com/chromium/chromium/main/DEPS

# shellcheck disable=SC3040
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR}" "${_BLDDIR}"

  _CFLAGS="${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} -ffile-prefix-map=$(pwd)="
  _CFLAGS="${_CFLAGS} -lpthread -lws2_32"  # libs for tests

  options=''

  [ "${_CPU}" = 'x86' ] && cpu='x86'
  [ "${_CPU}" = 'x64' ] && cpu='x86_64'
  if [ "${_CPU}" = 'a64' ]; then
    cpu='ARM64'; options="${options} -DOPENSSL_NO_ASM=ON"  # FIXME
  fi

  options="${options} -DOPENSSL_SMALL=OFF"  # ON reduces curl binary sizes by ~300 KB

  # Patch the build to omit debug info. This results in 50% smaller footprint
  # for each ${_BLDDIR}. As of llvm 14.0.6, llvm-strip does an imperfect job
  # when deleting -ggdb debug info and ends up having ~100 bytes of metadata
  # different (e.g. in windows.c.obj, a_utf8.c.obj, but not a_octet.c.obj)
  # across build host platforms. Fixed either by patching out this flag here,
  # or by running binutils strip on the result. binutils strip do not support
  # ARM64, so patch it out in that case.
# sed -i.bak 's/ -ggdb//g' ./CMakeLists.txt

  # shellcheck disable=SC2086
  cmake . -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${options} \
    "-DCMAKE_SYSTEM_PROCESSOR=${cpu}" \
    '-DBUILD_SHARED_LIBS=OFF' \
    '-DCMAKE_ASM_NASM_FLAGS=--reproducible' \
    "-DCMAKE_C_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL}" \
    "-DCMAKE_CXX_FLAGS=-Wno-unused-command-line-argument ${_CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs=2 install "DESTDIR=$(pwd)/${_PKGDIR}"

  _pkg="${_PP}"  # DESTDIR= + _PREFIX

  # List files created
  find "${_pkg}"

  # Make steps for determinism

  readonly _ref='README.md'

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_pkg}"/lib/*.a

  touch -c -r "${_ref}" "${_pkg}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_pkg}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(mktemp -d)/${_BAS}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_pkg}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_pkg}"/lib/*.a             "${_DST}/lib"
  cp -f -p LICENSE                       "${_DST}/LICENSE.txt"
  cp -f -p README.md                     "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
