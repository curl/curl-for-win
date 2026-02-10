#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# WARNING: libssh uses hard-coded world-writable paths (e.g. /etc/...) to read
#          its security critical configuration from, making it vulnerable to
#          attacks on Windows.
#          Do not use this component till there is a fix for these.
#
#          v0.12.0 update:
#            https://gitlab.com/libssh/libssh-mirror/-/commit/6a7f19ec3486698bde3169161edf01ca11cca55f
#          This issue received a mitigation where the unixy hard-coded paths
#          are replaced with Windowsy ones by default, pointing to 'PROGRAMDATA'
#          env if set, or the hard-coded 'C:/ProgramData/ssh' otherwise. This
#          still potentially leaves systems/users vulnerable:
#
#          - libssh seems to support Windows older than XP. The concept of
#            ProgramData came with Vista, leaving earlier versions vulnerable.
#            (it does not affect curl-for-win, as it needs Vista or newer)
#
#          - The build-time value of 'PROGRAMDATA' env works as expected only
#            when the built binary is run on the same machine as it was built
#            on. Typically on Windows this is rarely the case. Individual
#            machines can have this directory customized or the OS installed
#            on a different drive. Windows has no guaranteed protected
#            directory across versions, configurations and installations.
#
#          - Same issue with the fallback value, which may be correct for
#            many/most systems, but not for all.
#            To fix both, this directory would need to be determined at
#            runtime, not build-time, via 'SHGetKnownFolderPath()'. The
#            fallback value would need to be something that works on all
#            supported systems, e.g. via 'WINDIR' or the Win32 API equivalent.
#            (or perhaps refuse to load config data from disk in such case.)
#            Similar to how libssh uses 'SHGetSpecialFolderPathA()' to figure
#            out the user home directory:
#            https://gitlab.com/libssh/libssh-mirror/-/blob/f13a8d7ced240456d9002460bfc243c3097e77e5/src/misc.c#L117
#
#          - There is no CMake option to directly customize 'GLOBAL_CONF_DIR',
#            as exists for its two derivatives 'GLOBAL_BIND_CONFIG' and
#            'GLOBAL_CLIENT_CONFIG'. It means, to keep them synced, one must
#            set 'PROGRAMDATA' env explicitly, aligned with the other two CMake
#            configuration settings.
#
#          - After this patch, (cross-)builders have to clear/set 'PROGRAMDATA'
#            env to avoid being accidentally or maliciously set to something
#            undesired. IMO an explicit CMake option could be useful to
#            control/override this directory at build-time.
#
#          - Setting 'WITH_HERMETIC_USR' for the CMake build creates
#            a world-writable, vulnerable configuration on Windows by appending
#            the Windows absolute ProgramData path to '/usr',
#            via 'USR_GLOBAL_CLIENT_CONFIG' and 'USR_GLOBAL_BIND_CONFIG'. Also
#            via 'USR_GLOBAL_CONF_DIR', but even though this config value is set,
#            it does not seem to be used afterwards:
#            https://gitlab.com/libssh/libssh-mirror/-/blob/f13a8d7ced240456d9002460bfc243c3097e77e5/DefineOptions.cmake#L90-92
#            https://gitlab.com/libssh/libssh-mirror/-/blob/f13a8d7ced240456d9002460bfc243c3097e77e5/DefineOptions.cmake#L98-100
#
#          - Included (recursive) config files seem to be loaded from
#            a hard-coded '/etc/ssh' path, via 'ssh_config_make_absolute()':
#            https://gitlab.com/libssh/libssh-mirror/-/blob/f13a8d7ced240456d9002460bfc243c3097e77e5/src/config.c#L651-665
#
#          - I would find it useful to have a build-time option to fully prevent
#            loading global configuration from disk, making settings 'hermetic'
#            and determined solely at runtime by the user application. This may
#            be useful for non-Windows too.
#
#          - Documentation says ProgramData allows modification by the user
#            who created the file first (or any user on the machine?). This is
#            not necessarily the semantics expected for SSH global configuration
#            on multi-user machines.
#            Unless perhaps this user was a dedicated administrator, which is
#            not guaranteed and not enforceable from a library. Otherwise
#            a malicious application running under the local user can freely
#            alter the libssh global configuration.
#            In case the config files were created by a different user on the
#            same machine, that user may keep controlling global settings for
#            other users. A disk location with security properties similar to
#            the HKLM registry hive may be a better fit, perhaps
#            'FOLDERID_System' or 'FOLDERID_ProgramFiles'.
#            Refs:
#            https://learn.microsoft.com/windows/win32/shell/knownfolderid
#            https://learn.microsoft.com/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-folderlocations-programdata

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIRS:?}" "${_BLDDIR:?}"

  CPPFLAGS=''
  LIBS=''
  options=''

  if [ "${_OS}" = 'win' ]; then
    # Hack to force pthread to remain undetected and force falling back to
    # Windows native threading. If there is a better way, I could not find it.
    # Tried these without success:
    #   -DCMAKE_THREAD_PREFER_PTHREADS=OFF
    #   -DTHREADS_PREFER_PTHREAD_FLAG=OFF
    #   -DCMAKE_USE_WIN32_THREADS_INIT=ON
    CPPFLAGS+=' -Dpthread_create=func_not_existing'
  fi

  # Silence libssh API deprecation warnings when building libssh itself.
  CPPFLAGS+=' -DSSH_SUPPRESS_DEPRECATED'

  if [ -n "${_ZLIB}" ] && [ -d "../${_ZLIB}/${_PP}" ]; then
    options+=" -DZLIB_INCLUDE_DIR=${_TOP}/${_ZLIB}/${_PP}/include"
    options+=" -DZLIB_LIBRARY=${_TOP}/${_ZLIB}/${_PP}/lib/libz.a"
  else
    options+=' -DWITH_ZLIB=OFF'
  fi

  if [ -n "${_OPENSSL}" ] && [ -d "../${_OPENSSL}/${_PP}" ]; then
    options+=" -DOPENSSL_ROOT_DIR=${_TOP}/${_OPENSSL}/${_PP}"
    if [ "${_OPENSSL}" = 'boringssl' ] || [ "${_OPENSSL}" = 'awslc' ]; then

      # FIXME (upstream):
      # - It collides with wincrypt.h macros. Workaround:
      CPPFLAGS+=' -DNOCRYPT -D__WINCRYPT_H__'
      # - Wants to compile libcrypto_compat.c and assumes pre-OpenSSL 1.1
      #   non-opaque structures. Workaround:
      echo > src/libcrypto-compat.c
      # - Detects HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT, and assumes it means
      #   openssl/modes.h also exists, but with BoringSSL, it does not. Workaround:
      [ -d include/openssl ] || mkdir -p include/openssl
      touch include/openssl/modes.h
      # - libssh 0.10.0 started to enforce specific OpenSSL version numbers,
      #   but CMake's version detection (as of 4.2.1) is not aware of BoringSSL
      #   and fails to detect it. Work this around by the horrible hack of copying
      #   the necessary PP line where CMake is looking for it:
      i="${_TOP}/${_OPENSSL}/${_PP}/include/openssl"
      v="${i}/opensslv.h"
      if ! grep -q -a 'OPENSSL_VERSION_NUMBER' "${v}"; then
        l="$(grep --no-filename -a 'OPENSSL_VERSION_NUMBER' "${i}"/* | head -n 1)"
        tmp="${l}.tmp"
        touch -r "${v}" "${tmp}"
        printf '\n#if 0\n%s\n#endif\n' "${l}" >> "${v}"
        touch -r "${tmp}" "${v}"
        rm -f -- "${tmp}"
      fi

      [ "${_OS}" = 'win' ] && CPPFLAGS+=' -DWIN32_LEAN_AND_MEAN'
      LIBS+=' -lpthread'  # to detect EVP_aes_128_*
    elif [ "${_OPENSSL}" = 'libressl' ]; then
      # FIXME (upstream):
      # - Public function explicit_bzero() clashes with libressl.
      #   Workaround: put -lssh before -lcrypto.
      options+=' -DHAVE_OPENSSL_EVP_CHACHA20=0'  # FIXME (upstream): avoid detection to avoid build-time error: use of undeclared identifier 'EVP_PKEY_POLY1305'
      if [ "${_OS}" = 'win' ]; then
        CPPFLAGS+=' -DLIBRESSL_DISABLE_OVERRIDE_WINCRYPT_DEFINES_WARNING'
        LIBS+=' -lbcrypt'
        LIBS+=' -lws2_32'  # to detect EVP_aes_128_*
      fi
    elif [ "${_OPENSSL}" = 'openssl' ]; then
      CPPFLAGS+=' -DOPENSSL_SUPPRESS_DEPRECATED'
      if [ "${_OS}" = 'win' ]; then
        LIBS+=' -lbcrypt'
        LIBS+=' -lws2_32'  # to detect EVP_aes_128_*
      fi
    fi
  fi

  if [ "${_OS}" = 'win' ]; then
    _my_prefix='C:/Windows/System32/ssh'
    export PROGRAMDATA="${_my_prefix}"  # to set 'GLOBAL_CONF_DIR' for 'ssh_known_hosts' (as of v0.12.0)
  else
    _my_prefix='/etc/ssh'
  fi

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    -DGLOBAL_CLIENT_CONFIG="${_my_prefix}/ssh_config" \
    -DGLOBAL_BIND_CONFIG="${_my_prefix}/libssh_server_config" \
    -DBUILD_SHARED_LIBS=OFF \
    -DWITH_GSSAPI=OFF \
    -DWITH_NACL=OFF \
    -DWITH_SERVER=OFF \
    -DWITH_EXAMPLES=OFF \
    -DUNIT_TESTING=OFF \
    -DCMAKE_C_FLAGS="${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${CPPFLAGS} ${_LDFLAGS_GLOBAL} ${LIBS}"

  cmake --build "${_BLDDIR}"
  cmake --install "${_BLDDIR}" --prefix "${_PPS}"

  # Make steps for determinism

  readonly _ref='CHANGELOG'

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PPS}"/lib/*.a

  touch -c -r "${_ref}" "${_PPS}"/include/libssh/*.h
  touch -c -r "${_ref}" "${_PPS}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}"/include/libssh
  mkdir -p "${_DST}"/lib

  cp -f -p "${_PPS}"/include/libssh/*.h "${_DST}"/include/libssh/
  cp -f -p "${_PPS}"/lib/*.a            "${_DST}"/lib/
  cp -f -p CHANGELOG                    "${_DST}"/CHANGELOG.txt
  cp -f -p AUTHORS                      "${_DST}"/AUTHORS.txt
  cp -f -p COPYING                      "${_DST}"/COPYING.txt
  cp -f -p README.md                    "${_DST}"/

  ../_pkg.sh "$(pwd)/${_ref}"
)
