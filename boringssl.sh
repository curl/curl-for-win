#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# FIXME (upstream):
# - x64 mingw-w64 pthread ucrt static linking bug -> requires llvm-mingw
# - BoringSSL also supports native-Windows threading, but it uses
#   MSVC-specific hacks, thus cannot be enabled for MinGW:
#     https://github.com/google/boringssl/blob/master/crypto/thread_win.c
# - Building tests takes 3 minutes per target (on AppVeyor CI, at the time
#   of this writing) and consumes 9x the disk space for ${_BLDDIR}, that is
#   32MB -> 283MB (for x64).
#   Disabling them requires elaborate edits in ./CMakeList.txt.
# - A test object named trampoline-x86_64.asm.obj ends up in libcrypto.a.
# - nasm includes the first 18 bytes of the HOME directory in its output.
#   e.g. rdrand-x86_64.asm.obj. This only affects libcrypto.a.
#   This is intentionally written into a `.file` record and --reproducible
#   does not disable it. See nasm/output/outcoff.c/coff_write_symbols()
#   PR: https://github.com/netwide-assembler/nasm/pull/33 [RELEASED in v2.16]
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

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.' | sed 's/-cmake//')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  CFLAGS="-ffile-prefix-map=$(pwd)="
  LIBS='-lpthread'  # for tests
  options=''

  [ "${_CPU}" = 'x86' ] && cpu='x86'
  [ "${_CPU}" = 'x64' ] && cpu='x86_64'
  if [ "${_CPU}" = 'a64' ]; then
    # Once we enable ASM for ARM64, we will need to deal with stripping its
    # non-deterministic `.file` sections. We will need a fix in either
    # llvm-strip or NASM, or binutils strip getting ARM64 support.
    cpu='ARM64'; options="${options} -DOPENSSL_NO_ASM=ON"  # FIXME
  else
    options="${options} -DCMAKE_ASM_NASM_FLAGS=--reproducible"
  fi

  options="${options} -DOPENSSL_SMALL=OFF"  # ON reduces curl binary sizes by ~300 KB

  # Patch the build to omit debug info. This results in 50% smaller footprint
  # for each ${_BLDDIR}. As of llvm 14.0.6, llvm-strip does an imperfect job
  # when deleting -ggdb debug info and ends up having ~100 bytes of metadata
  # different (e.g. in windows.c.obj, a_utf8.c.obj, but not a_octet.c.obj)
  # across build host platforms. Fixed either by patching out this flag here,
  # or by running binutils strip on the result. binutils strip do not support
  # ARM64, so patch it out in that case.
  # Enable it for all targets for consistency.
  sed -i.bak 's/ -ggdb//g' ./CMakeLists.txt

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${options} \
    "-DCMAKE_SYSTEM_PROCESSOR=${cpu}" \
    '-DBUILD_SHARED_LIBS=OFF' \
    "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${LIBS}" \
    "-DCMAKE_CXX_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${_LDFLAGS_GLOBAL} ${_LIBS_GLOBAL} ${LIBS} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"

  make --directory="${_BLDDIR}" --jobs="${_JOBS}" install "DESTDIR=$(pwd)/${_PKGDIR}"

  # List files created
  find "${_PP}"

  # Make steps for determinism

  readonly _ref='README.md'

  # FIXME: llvm-strip (as of 14.0.6) has a few bugs:
  #        - produces different output across build hosts after stripping libs
  #          compiled with -ggdb.
  #        - fails to strip the `.file` record from NASM objects.
  #          (fixed by --reproducible with nasm v2.16)
  #        - fails to clear timestamps in NASM objects.
  #          (fixed by --reproducible with nasm v2.15.05)
  #        Work around them by running it through binutils strip. This works for
  #        x64 and x86, but not for ARM64.
  #
  # Most combinations/orders running binutils/llvm strip over the output results
  # in different output, and except pure llvm-strip, all seem to be
  # deterministic. We chose to run binutils first and llvm second. This way
  # llvm creates the result we publish.
  #
  # <strip sequence>                                <bytes>
  # libcrypto-noggdb.a                              2858080
  # libcrypto-noggdb-llvm.a                         2482620
  # libcrypto-noggdb-llvm-binutils.a                2488078
  # libcrypto-noggdb-llvm-binutils-llvm.a           2479904
  # libcrypto-noggdb-llvm-binutils-llvm-binutils.a  2488078
  # libcrypto-noggdb-binutils.a                     2465310
  # libcrypto-noggdb-binutils-llvm.a                2479888
  # libcrypto-noggdb-binutils-llvm-binutils.a       2488078
  # libcrypto-ggdb.a                                9642542
  # libcrypto-ggdb-llvm.a                           2482606
  # libcrypto-ggdb-llvm-binutils.a                  2488066
  # libcrypto-ggdb-llvm-binutils-llvm.a             2479890
  # libcrypto-ggdb-llvm-binutils-llvm-binutils.a    2488066
  # libcrypto-ggdb-binutils.a                       2465298
  # libcrypto-ggdb-binutils-llvm.a                  2479874
  # libcrypto-ggdb-binutils-llvm-binutils.a         2488066

  "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libssl.a

  if [ -n "${_STRIP_BINUTILS}" ]; then
    # FIXME: llvm-strip corrupts nasm objects as of LLVM v16.0.0
  # "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libcrypto.a

    # FIXME: Use binutils strip instead, directly on objects, to avoid
    #        binutils strip v2.40 error `invalid operation` when run on
    #        the whole lib:
    ../_clean-lib.sh --strip "${_STRIP_BINUTILS}" "${_PP}"/lib/libcrypto.a
  else
    # We do not yet use ASM with ARM64 builds,
    # making it safe to use llvm-strip:
    "${_STRIP}" --enable-deterministic-archives --strip-debug "${_PP}"/lib/libcrypto.a
  fi

  touch -c -r "${_ref}" "${_PP}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(realpath .)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib"
  cp -f -p LICENSE                      "${_DST}/LICENSE.txt"
  cp -f -p README.md                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
