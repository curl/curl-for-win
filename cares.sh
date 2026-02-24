#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# Issues (as of 1.34.6):
# - `-DCARES_SYMBOL_HIDING=ON` does not seem to work on macOS with clang for
#   example. The issue seems to be that CARES_EXTERN is set unconditionally
#   to default visibility and -fvisibility=hidden does not override that.
# - Compiler warnings when building for macOS with GCC.
# - Bad cmake configure performance.

# shellcheck disable=SC3040,SC2039
set -o xtrace -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

export _NAM _VER _OUT _BAS _DST

_NAM="$(basename "$0" | cut -f 1 -d '.')"
_VER="$1"

(
  cd "${_NAM}" || exit 0

  rm -r -f "${_PKGDIR:?}" "${_BLDDIR:?}"

  options=''

  # Pre-fill auto-detection values. Each dependency is built 36 times per
  # workflow run (in GHA alone). Avoid running hundreds of detections per
  # build, because detection results are almost always well-known in popular
  # environments. It saves several minutes in GHA and IIRC 10% of the total
  # build time on AppVeyor. Possibly quite a few of these would be possible
  # to optimize upstream, avoiding the tedium of collecting and maintaining
  # these prefills downstream.

  options+=' -DHAVE__fdiagnostics_color_always=1'
  options+=' -DHAVE__fno_omit_frame_pointer=1'
  options+=' -DHAVE__O0=1'
  options+=' -DHAVE__Waggregate_return=1'
  options+=' -DHAVE__Wall=1'
  options+=' -DHAVE__Wcast_align=1'
  options+=' -DHAVE__Wcast_qual=1'
  options+=' -DHAVE__Wdeclaration_after_statement=1'
  options+=' -DHAVE__Wdouble_promotion=1'
  options+=' -DHAVE__Werror_implicit_function_declaration=1'
  options+=' -DHAVE__Werror_implicit_int=1'
  options+=' -DHAVE__Wextra=1'
  options+=' -DHAVE__Wfloat_equal=1'
  options+=' -DHAVE__Wformat_security=1'
  options+=' -DHAVE__Winit_self=1'
  options+=' -DHAVE__Wmissing_braces=1'
  options+=' -DHAVE__Wmissing_declarations=1'
  options+=' -DHAVE__Wmissing_format_attribute=1'
  options+=' -DHAVE__Wmissing_include_dirs=1'
  options+=' -DHAVE__Wmissing_prototypes=1'
  options+=' -DHAVE__Wnested_externs=1'
  options+=' -DHAVE__Wno_long_long=1'
  options+=' -DHAVE__Wold_style_definition=1'
  options+=' -DHAVE__Wpacked=1'
  options+=' -DHAVE__Wpointer_arith=1'
  options+=' -DHAVE__Wredundant_decls=1'
  options+=' -DHAVE__Wshadow=1'
  options+=' -DHAVE__Wstrict_overflow=1'
  options+=' -DHAVE__Wstrict_prototypes=1'
  options+=' -DHAVE__Wundef=1'
  options+=' -DHAVE__Wunreachable_code=1'
  options+=' -DHAVE__Wunused=1'
  options+=' -DHAVE__Wvariadic_macros=1'
  options+=' -DHAVE__Wvla=1'
  options+=' -DHAVE__Wwrite_strings=1'

  if [ "${_CC}" = 'gcc' ]; then
    options+=' -DHAVE__fcolor_diagnostics=0'
    options+=' -DHAVE__Qunused_arguments=0'
    options+=' -DHAVE__Wconversion=1'
    options+=' -DHAVE__Werror_partial_availability=0'
    options+=' -DHAVE__Wimplicit_fallthrough_3=1'
    options+=' -DHAVE__Wjump_misses_init=1'
    options+=' -DHAVE__Wlogical_op=1'
    options+=' -DHAVE__Wno_coverage_mismatch=1'
    options+=' -DHAVE__Wpedantic=1'
    options+=' -DHAVE__Wsign_conversion=1'
    options+=' -DHAVE__Wtrampolines=1'
  else
    options+=' -DHAVE__fcolor_diagnostics=1'
    options+=' -DHAVE__Qunused_arguments=1'
    options+=' -DHAVE__Wconversion=1'
    options+=' -DHAVE__Werror_partial_availability=1'
    options+=' -DHAVE__Wimplicit_fallthrough_3=0'
    # TODO: enable for macOS once Apple clang 26.4+ becomes the default on the runner
    if [ "${_TOOLCHAIN}" != 'llvm-apple' ] && [ "${_CCVER}" -ge '21' ]; then
      options+=' -DHAVE__Wjump_misses_init=1'  # 12 builds
    else
      options+=' -DHAVE__Wjump_misses_init=0'  # 7 builds
    fi
    options+=' -DHAVE__Wlogical_op=0'
    options+=' -DHAVE__Wno_coverage_mismatch=0'
    options+=' -DHAVE__Wpedantic=1'
    options+=' -DHAVE__Wsign_conversion=1'
    options+=' -DHAVE__Wtrampolines=0'
  fi

  options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_res_servicename=0'
  options+=' -DHAVE___SYSTEM_PROPERTY_GET=0'
  options+=' -DHAVE_AF_INET6=1'
  options+=' -DHAVE_ASSERT_H=1'
  options+=' -DHAVE_CLOCK_GETTIME_MONOTONIC=1'
  options+=' -DHAVE_CLOSESOCKET_CAMEL=0'
  options+=' -DHAVE_CONNECT=1'
  options+=' -DHAVE_ERRNO_H=1'
  options+=' -DHAVE_FCNTL_H=1'
  options+=' -DHAVE_FIONBIO=1'
  options+=' -DHAVE_FREEADDRINFO=1'
  options+=' -DHAVE_GETADDRINFO=1'
  options+=' -DHAVE_GETENV=1'
  options+=' -DHAVE_GETHOSTNAME=1'
  options+=' -DHAVE_GETNAMEINFO=1'
  options+=' -DHAVE_GETTIMEOFDAY=1'
  options+=' -DHAVE_IF_INDEXTONAME=1'
  options+=' -DHAVE_IF_NAMETOINDEX=1'
  options+=' -DHAVE_INTTYPES_H=1'
  options+=' -DHAVE_IOCTLSOCKET_CAMEL=0'
  options+=' -DHAVE_LIMITS_H=1'
  options+=' -DHAVE_LONGLONG=1'
  options+=' -DHAVE_MEMORY_H=1'
  options+=' -DHAVE_NETINET6_IN6_H=0'
  options+=' -DHAVE_PF_INET6=1'
  options+=' -DHAVE_RECV=1'
  options+=' -DHAVE_RECVFROM=1'
  options+=' -DHAVE_SEND=1'
  options+=' -DHAVE_SENDTO=1'
  options+=' -DHAVE_SETSOCKOPT=1'
  options+=' -DHAVE_SIGNAL_H=1'
  options+=' -DHAVE_SO_NONBLOCK=0'
  options+=' -DHAVE_SOCKET_H=0'
  options+=' -DHAVE_SOCKET=1'
  options+=' -DHAVE_SOCKLEN_T=1'
  options+=' -DHAVE_SSIZE_T=1'
  options+=' -DHAVE_STAT=1'
  options+=' -DHAVE_STDBOOL_H=1'
  options+=' -DHAVE_STDINT_H=1'
  options+=' -DHAVE_STDLIB_H=1'
  options+=' -DHAVE_STRCASECMP=1'
  options+=' -DHAVE_STRDUP=1'
  options+=' -DHAVE_STRING_H=1'
  options+=' -DHAVE_STRINGS_H=1'
  options+=' -DHAVE_STRNCASECMP=1'
  options+=' -DHAVE_STRNCMPI=0'
  options+=' -DHAVE_STRNLEN=1'
  options+=' -DHAVE_STRUCT_ADDRINFO=1'
  options+=' -DHAVE_STRUCT_IN6_ADDR=1'
  options+=' -DHAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID=1'
  options+=' -DHAVE_STRUCT_SOCKADDR_IN6=1'
  options+=' -DHAVE_STRUCT_SOCKADDR_STORAGE=1'
  options+=' -DHAVE_STRUCT_TIMEVAL=1'
  options+=' -DHAVE_SYS_PARAM_H=1'
  options+=' -DHAVE_SYS_STAT_H=1'
  options+=' -DHAVE_SYS_TIME_H=1'
  options+=' -DHAVE_SYS_TYPES_H=1'
  options+=' -DHAVE_TIME_H=1'
  options+=' -DHAVE_UNISTD_H=1'
  options+=' -DM_NO_INLINE=0'

  if [ "${_OS}" = 'win' ]; then
    options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_clock_gettime=0'
    options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_gethostbyname=0'
    options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_socket=0'
    options+=' -DHAVE_ARC4RANDOM_BUF=0'
    options+=' -DHAVE_ARPA_INET_H=0'
    options+=' -DHAVE_ARPA_NAMESER_COMPAT_H=0'
    options+=' -DHAVE_ARPA_NAMESER_H=0'
    options+=' -DHAVE_AVAILABILITYMACROS_H=0'
    options+=' -DHAVE_CLOSESOCKET_CAMEL=0'
    options+=' -DHAVE_CLOSESOCKET=1'
    options+=' -DHAVE_CONNECTX=0'
    options+=' -DHAVE_CONVERTINTERFACEINDEXTOLUID=1'
    options+=' -DHAVE_CONVERTINTERFACELUIDTONAMEA=1'
    options+=' -DHAVE_DLFCN_H=0'
    options+=' -DHAVE_EPOLL=0'
    options+=' -DHAVE_FCNTL=0'
    options+=' -DHAVE_GETBESTROUTE2=1'
    options+=' -DHAVE_GETIFADDRS=0'
    options+=' -DHAVE_GETRANDOM=0'
    options+=' -DHAVE_GETSERVBYNAME_R=0'
    options+=' -DHAVE_GETSERVBYPORT_R=0'
    options+=' -DHAVE_GHBN_LIBSOCKET=0'
    options+=' -DHAVE_IFADDRS_H=0'
    options+=' -DHAVE_INET_NET_PTON=0'
    options+=' -DHAVE_IOCTL_SIOCGIFADDR=0'
    options+=' -DHAVE_IOCTL=0'
    options+=' -DHAVE_IOCTLSOCKET_CAMEL=0'
    options+=' -DHAVE_IOCTLSOCKET=1'
    options+=' -DHAVE_IPHLPAPI_H=1'
    options+=' -DHAVE_LIBNETWORK=0'
    options+=' -DHAVE_LIBNSL=0'
    options+=' -DHAVE_LIBRT=0'
    options+=' -DHAVE_MSG_NOSIGNAL=0'
    options+=' -DHAVE_MSWSOCK_H=1'
    options+=' -DHAVE_NETIOAPI_H=1'
    options+=' -DHAVE_NOTIFYIPINTERFACECHANGE=1'
    options+=' -DHAVE_NTDEF_H=1'
    options+=' -DHAVE_NTSTATUS_H=1'
    options+=' -DHAVE_REGISTERWAITFORSINGLEOBJECT=1'
    options+=' -DHAVE_SOCKET_LIBSOCKET=0'
    options+=' -DHAVE_KQUEUE=0'
    options+=' -DHAVE_MALLOC_H=1'
    options+=' -DHAVE_MEMMEM=0'
    options+=' -DHAVE_NET_IF_H=0'
    options+=' -DHAVE_NETDB_H=0'
    options+=' -DHAVE_NETINET_IN_H=0'
    options+=' -DHAVE_NETINET_TCP_H=0'
    options+=' -DHAVE_NETINET6_IN6_H=0'
    options+=' -DHAVE_O_NONBLOCK=0'
    options+=' -DHAVE_PIPE=0'
    options+=' -DHAVE_PIPE2=0'
    options+=' -DHAVE_POLL_H=0'
    options+=' -DHAVE_POLL=0'
    options+=' -DHAVE_RES_SERVICENAME_IN_LIBRESOLV=0' # see also _CARES_FUNC_IN_LIB_GLOBAL_res_servicename
    options+=' -DHAVE_SO_NONBLOCK=0'
    options+=' -DHAVE_SOCKET_H=0'
    options+=' -DHAVE_STRCMPI=1'
    options+=' -DHAVE_STRICMP=1'
    options+=' -DHAVE_STRNCMPI=0'
    options+=' -DHAVE_STRNICMP=1'
    options+=' -DHAVE_STROPTS_H=0'
    options+=' -DHAVE_SYS_EPOLL_H=0'
    options+=' -DHAVE_SYS_EVENT_H=0'
    options+=' -DHAVE_SYS_IOCTL_H=0'
    options+=' -DHAVE_SYS_RANDOM_H=0'
    options+=' -DHAVE_SYS_SELECT_H=0'
    options+=' -DHAVE_SYS_SOCKET_H=0'
    options+=' -DHAVE_SYS_SOCKIO_H=0'
    options+=' -DHAVE_SYS_UIO_H=0'
    options+=' -DHAVE_TYPE_SOCKET=1'
    options+=' -DHAVE_WRITEV=0'
    options+=' -DHAVE_WINDOWS_H=1'
    options+=' -DHAVE_WINSOCK_H=1'
    options+=' -DHAVE_WINSOCK2_H=1'
    options+=' -DHAVE_WINTERNL_H=1'
    options+=' -DHAVE_WS2TCPIP_H=1'
  else  # linux || mac
    options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_clock_gettime=1'
    options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_gethostbyname=1'
    options+=' -D_CARES_FUNC_IN_LIB_GLOBAL_socket=1'
    if [ "${_CRT}" = 'gnu' ] || [ "${_OS}" = 'mac' ]; then  # glibc || mac
      options+=' -DHAVE_ARC4RANDOM_BUF=1'  # 10 builds
    else
      options+=' -DHAVE_ARC4RANDOM_BUF=0'  # 16 builds (not it musl)
    fi
    options+=' -DHAVE_ARPA_INET_H=1'
    options+=' -DHAVE_ARPA_NAMESER_COMPAT_H=1'
    options+=' -DHAVE_ARPA_NAMESER_H=1'
    options+=' -DHAVE_CLOSESOCKET_CAMEL=0'
    options+=' -DHAVE_CLOSESOCKET=0'
    options+=' -DHAVE_CONVERTINTERFACEINDEXTOLUID=0'
    options+=' -DHAVE_CONVERTINTERFACELUIDTONAMEA=0'
    options+=' -DHAVE_DLFCN_H=1'
    options+=' -DHAVE_FCNTL=1'
    options+=' -DHAVE_GETBESTROUTE2=0'
    options+=' -DHAVE_GETIFADDRS=1'
    options+=' -DHAVE_IFADDRS_H=1'
    options+=' -DHAVE_INET_NTOP=1'
    options+=' -DHAVE_INET_PTON=1'
    options+=' -DHAVE_IOCTL_SIOCGIFADDR=1'
    options+=' -DHAVE_IOCTL=1'
    options+=' -DHAVE_IOCTLSOCKET_CAMEL=0'
    options+=' -DHAVE_IOCTLSOCKET=0'
    options+=' -DHAVE_MEMMEM=1'
    options+=' -DHAVE_MSG_NOSIGNAL=1'
    options+=' -DHAVE_NET_IF_H=1'
    options+=' -DHAVE_NETDB_H=1'
    options+=' -DHAVE_NETINET_IN_H=1'
    options+=' -DHAVE_NETINET_TCP_H=1'
    options+=' -DHAVE_NETINET6_IN6_H=0'
    options+=' -DHAVE_NOTIFYIPINTERFACECHANGE=0'
    options+=' -DHAVE_O_NONBLOCK=1'
    options+=' -DHAVE_PIPE=1'
    options+=' -DHAVE_POLL_H=1'
    options+=' -DHAVE_POLL=1'
    options+=' -DHAVE_PTHREAD_H=1'
    options+=' -DHAVE_PTHREAD_INIT=0'
    options+=' -DHAVE_PTHREAD_NP_H=0'
    options+=' -DHAVE_REGISTERWAITFORSINGLEOBJECT=0'
    options+=' -DHAVE_SO_NONBLOCK=0'
    options+=' -DHAVE_SOCKET_H=0'
    options+=' -DHAVE_STRCMPI=0'
    options+=' -DHAVE_STRICMP=0'
    options+=' -DHAVE_STRNCMPI=0'
    options+=' -DHAVE_STRNICMP=0'
    options+=' -DHAVE_SYS_IOCTL_H=1'
    options+=' -DHAVE_SYS_RANDOM_H=1'
    options+=' -DHAVE_SYS_SELECT_H=1'
    options+=' -DHAVE_SYS_SOCKET_H=1'
    options+=' -DHAVE_SYS_UIO_H=1'
    options+=' -DHAVE_TYPE_SOCKET=0'
    options+=' -DHAVE_WRITEV=1'

    if [ "${_OS}" = 'linux' ]; then
      options+=' -DHAVE_AVAILABILITYMACROS_H=0'
      options+=' -DHAVE_CONNECTX=0'
      options+=' -DHAVE_EPOLL=1'
      options+=' -DHAVE_GETRANDOM=1'
      options+=' -DHAVE_GETSERVBYNAME_R=1'
      options+=' -DHAVE_GETSERVBYPORT_R=1'
      options+=' -DHAVE_INET_NET_PTON=0'
      options+=' -DHAVE_KQUEUE=0'
      options+=' -DHAVE_MALLOC_H=1'
      options+=' -DHAVE_PIPE2=1'
      options+=' -DHAVE_RES_SERVICENAME_IN_LIBRESOLV=0'
      if [ "${_CRT}" = 'musl' ]; then
        options+=' -DHAVE_STROPTS_H=1'  # 16 builds
      else
        options+=' -DHAVE_STROPTS_H=0'  # 10 builds
      fi
      options+=' -DHAVE_SYS_EPOLL_H=1'
      options+=' -DHAVE_SYS_EVENT_H=0'
      options+=' -DHAVE_SYS_SOCKIO_H=0'
    elif [ "${_OS}" = 'mac' ]; then
      options+=' -DHAVE_AVAILABILITYMACROS_H=1'
      options+=' -DHAVE_CONNECTX=1'
      options+=' -DHAVE_EPOLL=0'
      options+=' -DHAVE_GETRANDOM=0'
      options+=' -DHAVE_GETSERVBYNAME_R=0'
      options+=' -DHAVE_GETSERVBYPORT_R=0'
      options+=' -DHAVE_INET_NET_PTON=1'
      options+=' -DHAVE_KQUEUE=1'
      options+=' -DHAVE_MALLOC_H=0'
      options+=' -DHAVE_PIPE2=0'
      options+=' -DHAVE_RES_SERVICENAME_IN_LIBRESOLV=1'
      options+=' -DHAVE_STROPTS_H=0'
      options+=' -DHAVE_SYS_EPOLL_H=0'
      options+=' -DHAVE_SYS_EVENT_H=1'
      options+=' -DHAVE_SYS_SOCKIO_H=1'

      options+=' -DIOS=0'
      options+=' -DIOS_V10=0'
      options+=' -DMACOS_V1012=0'
    fi
  fi

  # Special cases
  if [ "${_OS}" = 'mac' ]; then
    if [ "${_CC}" = 'gcc' ]; then
      options+=' -DHAVE__Wpedantic=0 -DHAVE__Wsign_conversion=0 -DHAVE__Wconversion=0'
    fi
    if [ "${_OSVER}" -lt '1011' ]; then
      options+=' -DHAVE_CONNECTX=0'  # connectx() requires 10.11
    fi
  fi

  # shellcheck disable=SC2086
  cmake -B "${_BLDDIR}" ${_CMAKE_GLOBAL} ${options} \
    -DCARES_SYMBOL_HIDING=ON \
    -DCARES_STATIC=ON \
    -DCARES_STATIC_PIC=ON \
    -DCARES_SHARED=OFF \
    -DCARES_BUILD_TESTS=OFF \
    -DCARES_BUILD_CONTAINER_TESTS=OFF \
    -DCARES_BUILD_TOOLS=OFF \
    -DCMAKE_C_FLAGS="${_CFLAGS_GLOBAL_CMAKE} ${_CFLAGS_GLOBAL} ${_CPPFLAGS_GLOBAL} ${_LDFLAGS_GLOBAL}"

  cmake --build "${_BLDDIR}"
  cmake --install "${_BLDDIR}" --prefix "${_PP}"

  # Delete .pc files
  rm -r -f "${_PP}"/lib/pkgconfig

  # Make steps for determinism

  readonly _ref='RELEASE-NOTES.md'

  # shellcheck disable=SC2086
  "${_STRIP_LIB}" ${_STRIPFLAGS_LIB} "${_PP}"/lib/*.a

  touch -c -r "${_ref}" "${_PP}"/include/*.h
  touch -c -r "${_ref}" "${_PP}"/lib/*.a

  # Create package

  _OUT="${_NAM}-${_VER}${_REVSUFFIX}${_PKGSUFFIX}"
  _BAS="${_NAM}-${_VER}${_PKGSUFFIX}"
  _DST="$(pwd)/_pkg"; rm -r -f "${_DST}"

  mkdir -p "${_DST}"/include
  mkdir -p "${_DST}"/lib

  cp -f -p "${_PP}"/include/*.h "${_DST}"/include/
  cp -f -p "${_PP}"/lib/*.a     "${_DST}"/lib/
  cp -f -p README.md            "${_DST}"/
  cp -f -p RELEASE-NOTES.md     "${_DST}"/
  cp -f -p LICENSE.md           "${_DST}"/

  ../_pkg.sh "$(pwd)/${_ref}"
)
