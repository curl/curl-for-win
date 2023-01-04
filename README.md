<!--
Copyright 2014-present Viktor Szakats
SPDX-License-Identifier: CC-BY-SA-4.0
-->
[![License](https://raw.githubusercontent.com/curl/curl-for-win/main/MIT.svg?sanitize=1)](LICENSE.md)
[![Build status](https://ci.appveyor.com/api/projects/status/8yf6xjgq7u0cm013/branch/main?svg=true)](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main)

# Reproducible curl binaries for Windows

- You can [download](https://curl.se/windows/) the packages
  in `.zip` or `.tar.xz` formats,<br>PGP signed with:
  [`002C 1689 65BA C220 2118  408B 4ED8 5DF9 BB3D 0DE8`](https://raw.githubusercontent.com/curl/curl-for-win/main/sign-pkg-public.asc)
- Standalone `curl.exe` and `libcurl.dll`. Static libraries included.
- Vista and
  [Universal CRT](https://devblogs.microsoft.com/cppblog/introducing-the-universal-crt/)
  required.
- [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3) and
  [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support,
  and [more](#features).
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
- Built with
  [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29)
  options enabled.
- Binaries use
  [SEH](https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH),
  except x86, which uses [DWARF](https://en.wikipedia.org/wiki/DWARF).
- We verify components using SHA-256, and PGP where provided.
- We build [reproducible](https://reproducible-builds.org/) binaries,
  producing the same hash given the same input sources and C compiler.
- Patching policy: No local patches. We may apply patches if already merged
  upstream or &mdash; for showstoppers &mdash; had them submitted with fair
  confidence of getting merged.
- We plan to switch the default TLS backend to BoringSSL. This fixes a
  long-standing [vulnerability](https://curl.se/docs/CVE-2019-5443.html). It
  also makes binaries 30% smaller. Downsides are no API/ABI guaranties, pthread
  dependence and no TLS-SRP support. Another option is LibreSSL 3.7.x stable.
- You can look up our package hashes in lines starting with `SHA` in the
  [build log](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main).
- Packages built across host platforms do not have identical hashes due to
  slightly different build options and toolchain builds/versions. Except
  `llvm-mingw` builds, which are reproducible across platforms. ARM64 and
  BoringSSL builds are such by default.
- We code-sign with a self-signed certificate, and avoid trusted timestamps
  for reproducibility.

# Features

Default build with OpenSSL (QUIC [fork](https://github.com/quictls/openssl/)),
and [Schannel](https://learn.microsoft.com/windows/win32/com/schannel)
runtime-selectable option:
```
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe TLS-SRP UnixSockets zstd
```
<details><summary>Alternate configurations with different footprints:</summary><p>

```
"big":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM PSL SPNEGO SSL SSPI threadsafe         UnixSockets zstd

"boringssl":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets zstd

"noh3", HTTP/2:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2       HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe TLS-SRP UnixSockets zstd

"mini", Schannel, without brotli and zstd:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS        gsasl HSTS HTTP2                   IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets

"micro", without libssh2 and gsasl:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS              HSTS HTTP2                   IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets

"nano", HTTP/1.1:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp ws wss
Features:         AsynchDNS              HSTS                         IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets

"pico", HTTP/1.1-only:
Protocols:                                   http https
Features:         AsynchDNS              HSTS                             IPv6          Largefile libz                          SSL SSPI threadsafe         UnixSockets
```
</p></details>

# Downloads

* Latest version:
  <br><https://curl.se/windows/>
* Specific versions, back to 7.80.0:<br>
  `https://curl.se/windows/dl-<curl-version>[_<build-number>]/`
  <br>Examples:
  <br><https://curl.se/windows/dl-7.80.0/>
  <br><https://curl.se/windows/dl-7.83.1_2/>

# Build logs

<https://ci.appveyor.com/project/curlorg/curl-for-win/history>

# Guarantees and Liability

See [LICENSE](LICENSE.md).

Information in this document is subject to change without notice and does
not represent or imply any future commitment by the participants of the
project.

---
This document &copy;&nbsp;2014&ndash;present [Viktor Szakats](https://vsz.me/)<br>
[![Creative Commons Attribution-ShareAlike 4.0](https://raw.githubusercontent.com/curl/curl-for-win/main/cc-by-sa.svg?sanitize=1)](https://creativecommons.org/licenses/by-sa/4.0/)
