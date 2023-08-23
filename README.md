<!--
Copyright (C) Viktor Szakats
SPDX-License-Identifier: CC-BY-SA-4.0
-->
[![Build status](https://ci.appveyor.com/api/projects/status/8yf6xjgq7u0cm013/branch/main?svg=true)](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main)
[![Daily status](https://github.com/curl/curl-for-win/actions/workflows/daily.yml/badge.svg)](https://github.com/curl/curl-for-win/actions/workflows/daily.yml)

# Reproducible curl binaries for Windows

- **We are switching the default TLS backend to LibreSSL upon the next curl
  release when LibreSSL 3.8.x stable becomes available. This fixes a
  long-standing OpenSSL
  [vulnerability](https://curl.se/docs/CVE-2019-5443.html). It also makes
  binaries 40% smaller. Major crypto and curl features remain the same.**
- [Download](https://curl.se/windows/) our
  `.zip` or `.tar.xz` packages,<br>PGP signed with:
  [`002C 1689 65BA C220 2118  408B 4ED8 5DF9 BB3D 0DE8`](https://raw.githubusercontent.com/curl/curl-for-win/main/sign-pkg-public.asc)
- Standalone `curl.exe` and `libcurl.dll`. Static libraries included.
- Vista and
  [Universal CRT](https://devblogs.microsoft.com/cppblog/introducing-the-universal-crt/)
  required.
- [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3),
  [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support,
  and [more](#features).
- ARM64 builds are
  [Control Flow Guard](https://learn.microsoft.com/windows/win32/secbp/control-flow-guard)
  enabled [EXPERIMENTAL].
- Transparent builds, using open source code, run in
  [public](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main),
  with auditable [logs](#build-logs).
- [LLVM/Clang](https://clang.llvm.org/) build environment with
  [`mingw-w64`](https://sourceforge.net/p/mingw-w64/) via
  [Debian](https://packages.debian.org/testing/mingw-w64),
  [Homebrew](https://formulae.brew.sh/formula/mingw-w64),
  [MSYS2](https://www.msys2.org/).
  [`llvm-mingw`](https://github.com/mstorsjo/llvm-mingw) for ARM64.
- Cross-built and published from Linux via
  [AppVeyor CI](https://www.appveyor.com/). Using reproducible OS image
  [`debian:testing-slim`](https://github.com/debuerreotype/docker-debian-artifacts/tree/dist-amd64/testing/slim)
  via [Docker](https://hub.docker.com/_/debian/).
- We verify components using SHA-256, and PGP where provided.
- We build [reproducible](https://reproducible-builds.org/) binaries,
  producing the same hash given the same input sources and C compiler.
- Patching policy: No local patches. We may apply patches if already merged
  upstream or &mdash; for showstoppers &mdash; had them submitted with fair
  confidence of getting merged.
- You can look up our package hashes in lines starting with `SHA` in the
  [build log](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main).
- Packages built across host platforms do not have identical hashes due to
  slightly different build options and toolchain builds/versions. Except
  `llvm-mingw` builds, which are reproducible across platforms. ARM64 and
  BoringSSL builds are such by default.
- We code-sign with a self-signed certificate, and avoid trusted timestamps
  for reproducibility.

# Features

Uses [quictls](https://github.com/quictls/openssl/),
with runtime-selectable option
[Schannel](https://learn.microsoft.com/windows/win32/com/schannel):
```
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli       HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe UnixSockets zstd
```
<details><summary>Alternate configurations with different footprints:</summary><p>

```
"big":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM PSL SPNEGO SSL SSPI threadsafe UnixSockets zstd

"boringssl":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli       HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe UnixSockets zstd

"noh3", HTTP/2:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli       HSTS HTTP2       HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe UnixSockets zstd

"mini", without brotli and zstd, with OS TLS backend (Schannel, SecureTransport) if available:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS              HSTS HTTP2       HTTPS-proxy IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe UnixSockets

"micro", without libssh2:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS              HSTS HTTP2       HTTPS-proxy IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe UnixSockets

"nano", HTTP/1.1:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp ws wss
Features:         AsynchDNS              HSTS             HTTPS-proxy IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe UnixSockets

"pico", HTTP/1.1-only:
Protocols:                                   http https
Features:         AsynchDNS              HSTS             HTTPS-proxy     IPv6          Largefile libz                          SSL SSPI threadsafe UnixSockets
```
</p></details>

# Downloads

* Latest version:
  <br><https://curl.se/windows/>
* Specific versions, back to 8.2.0:<br>
  `https://curl.se/windows/dl-<curl-version>_<build-1-to-N>/`
  <br>Example:
  <br><https://curl.se/windows/dl-8.2.0_1/>

# Build logs

<https://ci.appveyor.com/project/curlorg/curl-for-win/history>

# Unstable/development daily builds

<https://github.com/curl/curl-for-win/actions/workflows/daily.yml>

# Guarantees and Liability

See [LICENSE](LICENSE.md).

Information in this document is subject to change without notice and does
not represent or imply any future commitment by the participants of the
project.

---
This document &copy; [Viktor Szakats](https://vsz.me/),
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
