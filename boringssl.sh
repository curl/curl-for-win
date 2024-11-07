#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Requires macOS 10.13

# FIXME (upstream):
# - x64 mingw-w64 pthread ucrt static linking bug -> requires llvm-mingw
#   Likely fixed in mingw-w64 12.0.0.
#   https://sourceforge.net/p/mingw-w64/mingw-w64/ci/ad2b46ca1e603872f62f83eaaff9e5ef77c99500/
#   https://github.com/mirror/mingw-w64/commit/ad2b46ca1e603872f62f83eaaff9e5ef77c99500
# - as of 4fe29ebc hacks are needed to avoid build issues. grep for the hash
#   to find them.
#   Does not affect AWS-LC.
# - BoringSSL also supports native-Windows threading, but it uses
#   MSVC-specific hacks, thus cannot be enabled for MinGW:
#     https://github.com/google/boringssl/blob/master/crypto/thread_win.c
#   Possible solution:
#     https://github.com/dotnet/runtime/blob/cbca5083d3e69f2bd25e397f8894d94d7763a13a/src/mono/mono/mini/mini-windows-tls-callback.c#L56
# - managed to patch BoringSSL to use native Windows threads and thus be
#   able to drop pthreads. curl crashes (with or without this patch.)
# - as of 4fe29ebc, BoringSSL uses C++, so dependents must be built with
#   static standard C++ library. static libunwind is also needed e.g. when
#   using llvm-mingw. Integrating all of this is non-trivial. When not
#   using llvm-mingw, pthreads is necessary again, but it does not trigger
#   the static pthreads linking bug (undefined reference to `_setjmp') we
#   hit earlier.
# - Building tests takes 3x time per target (on AppVeyor CI, at the time
#   of this writing) and consumes 5x the disk space for ${_BLDDIR}, that is
#   17MB -> 79MB (for x64, with ASM and -gddb disabled).
#   Disabling them requires patching ./CMakeList.txt.
#   This is fixed in AWS-LC fork with a CMake option.
# - Objects built on different OSes result in a few byte differences.
#   e.g. windows.c.obj, a_utf8.c.obj. But not a_octet.c.obj.
# - AWS-LC force-sets _WIN32_WINNT to _WIN32_WINNT_WIN7. The Windows target
#   should be up to the builder and not something for the project to set
#   unconditionally. If the selected version is too old, the build should
#   bail out. Either way, AWS-LC requires Win7, which is higher than the
#   Vista curl-for-win guarantees. But only for MinGW builds, as a way
#   to bump up the default, possibly as a workaround.
# - AWS-LC: symbols are not hidden, making _info-bin.sh fail.
# - AWS-LC: requires SSE2 for x86 builds with ASM enabled.
# - AWS-LC: fails to build on mac-gcc-arm64.

# https://github.com/aws/aws-lc

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

_NAM="$(basename "$0" | cut -f 1 -d '.')"; [ -n "${2:-}" ] && _NAM="$2"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  [ "${CW_DEV_INCREMENTAL:-}" != '1' ] && rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  CFLAGS="-ffile-prefix-map=$(pwd)="
  CPPFLAGS=''
  LIBS='-lpthread'  # for tests
  options=''

  if false || [ "${_CPU}" = 'r64' ]; then
    # to avoid (as of 4fe29ebc):
    #   ld.lld: error: undefined symbol: fiat_p256_adx_mul
    #   >>> referenced by libcrypto.a(bcm.o):(fiat_p256_mul)
    #   ld.lld: error: undefined symbol: fiat_p256_adx_sqr
    #   >>> referenced by libcrypto.a(bcm.o):(fiat_p256_square)
    # This is caused by a missing nasm implementation for these,
    # yet referencing them for gcc-based x64 builds, also on Windows,
    # which always use nasm. mingw-w64 builds hit constellation.
    # Fixed via a local patch.
    options+=' -DOPENSSL_NO_ASM=ON'
  else
    if [ "${_OS}" = 'win' ] && [ "${_CPU}" != 'a64' ]; then
      # nasm is used for Windows x64 and x86
      options+=' -DCMAKE_ASM_NASM_FLAGS=--reproducible'
    fi
    if [ "${_NAM}" = 'awslc' ] && [ "${_CPU}" = 'x86' ]; then
      CFLAGS+=' -msse2'
    fi
  fi

  # Workaround for Windows x64 llvm 16 breakage as of 85081c6b:
  # In file included from ./boringssl/crypto/curve25519/curve25519_64_adx.c:17:
  # ./boringssl/crypto/curve25519/../../third_party/fiat/curve25519_64_adx.h:40:11: error: call to undeclared function '_umul128'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
  #   *out1 = _umul128(arg1, arg2, &t);
  #           ^
  if [ "${_OS}" = 'win' ] && [ "${_CPU}" = 'x64' ] && [ "${_CC}" = 'llvm' ]; then
    options+=' -DOPENSSL_SMALL=ON'
  else
    options+=' -DOPENSSL_SMALL=OFF'  # ON reduces curl binary sizes by ~300 KB
  fi

  if [ "${CW_DEV_INCREMENTAL:-}" != '1' ] || [ ! -d "${_BLDDIR}" ]; then
    if [ "${_NAM}" = 'awslc' ]; then
      options+=' -DBUILD_TESTING=OFF'
      options+=' -DBUILD_TOOL=OFF'
      options+=' -DDISABLE_GO=ON'
      options+=' -DDISABLE_PERL=ON'

      if [ "${_OS}" = 'win' ]; then
        # Avoid deprecation warning triggered by mingw-w64 inside clang 19
        CPPFLAGS+=' -D_CLANG_DISABLE_CRT_DEPRECATION_WARNINGS'
      fi

      # Patch out to avoid redefinition errors
      sed -i.bak 's/-D_WIN32_WINNT=_WIN32_WINNT_WIN7//g' ./CMakeLists.txt
    else
      # Patch the build to omit debug info. This results in 50% smaller footprint
      # for each ${_BLDDIR}. As of llvm 14.0.6, llvm-strip does an imperfect job
      # when deleting -ggdb debug info and ends up having ~100 bytes of metadata
      # different (e.g. in windows.c.obj, a_utf8.c.obj, but not a_octet.c.obj)
      # across build host platforms. Fixed either by patching out this flag here,
      # or by running binutils strip on the result. binutils strip do not support
      # ARM64, so patch it out in that case.
      # Enable it for all targets for consistency.
      sed -i.bak 's/ -ggdb//g' ./CMakeLists.txt

      # Skip building test components
      echo 'set_target_properties(decrepit bssl_shim test_fips boringssl_gtest test_support_lib urandom_test crypto_test ssl_test decrepit_test all_tests pki pki_test run_tests PROPERTIES EXCLUDE_FROM_ALL TRUE)' >> ./CMakeLists.txt
    fi

    # shellcheck disable=SC2086
    cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${_CMAKE_CXX_GLOBAL} ${_CMAKE_ASM_GLOBAL} ${options} \
      '-DBUILD_SHARED_LIBS=OFF' \
      "-DCMAKE_C_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LIBS}" \
      "-DCMAKE_CXX_FLAGS=${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CFLAGS} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LIBS} ${_CXXFLAGS_GLOBAL} ${_LDFLAGS_CXX_GLOBAL}"
  fi

  cmake --build "${_BLDDIR}"  # --verbose
  cmake --install "${_BLDDIR}" --prefix "${_PP}"

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

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libssl.a

  if [ -n "${_STRIP_BINUTILS}" ]; then
    # FIXME: llvm-strip corrupts nasm objects as of LLVM v16.0.0
    # shellcheck disable=SC2086
  # "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libcrypto.a

    # FIXME: Use binutils strip instead, directly on objects, to avoid
    #        binutils strip v2.40 error `invalid operation` when run on
    #        the whole lib:
    ../_clean-lib.sh --strip "${_STRIP_BINUTILS}" "${_PP}"/lib/libcrypto.a
  else
    # shellcheck disable=SC2086
    "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/libcrypto.a
  fi

  touch -c -r "${_ref}" "${_PP}"/include/openssl/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}/include/openssl"
  mkdir -p "${_DST}/lib"

  cp -f -p "${_PP}"/include/openssl/*.h "${_DST}/include/openssl/"
  cp -f -p "${_PP}"/lib/*.a             "${_DST}/lib"
  cp -f -p LICENSE                      "${_DST}/LICENSE.txt"
  cp -f -p README.md                    "${_DST}/"

  ../_pkg.sh "$(pwd)/${_ref}"
)
