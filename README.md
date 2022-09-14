[![License](https://raw.githubusercontent.com/curl/curl-for-win/main/MIT.svg?sanitize=1)](LICENSE.md)
[![Build status](https://ci.appveyor.com/api/projects/status/8yf6xjgq7u0cm013/branch/main?svg=true)](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main)

# Reproducible curl binaries for Windows

- We provide binary packages in `.zip` and `.tar.xz` formats,
  signed with PGP key:
  <br>[`002C 1689 65BA C220 2118  408B 4ED8 5DF9 BB3D 0DE8`](https://raw.githubusercontent.com/curl/curl-for-win/main/sign-pkg-public.asc)
- Standalone `curl.exe` and `libcurl.dll`.
- Vista with
  [Universal CRT](https://devblogs.microsoft.com/cppblog/introducing-the-universal-crt/)
  required.
- Packages ship with all necessary static libraries.
- curl/libcurl have
  [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3) and
  [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support enabled.
  Detailed feature list [below](#features).
- Transparent builds, using open source code, and running them in
  [public](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main),
  with auditable [logs](#build-logs).
- Build environment is [LLVM/Clang](https://clang.llvm.org/) with
  [`mingw-w64`](https://sourceforge.net/p/mingw-w64/) via
  [Debian](https://packages.debian.org/testing/mingw-w64),
  [Homebrew](https://formulae.brew.sh/formula/mingw-w64),
  [MSYS2](https://www.msys2.org/).
  [`llvm-mingw`](https://github.com/mstorsjo/llvm-mingw) for ARM64.
- Binaries cross-built and published from Linux
  via [AppVeyor CI](https://www.appveyor.com/). Using reproducible OS image
  [`debian:testing-slim`](https://github.com/debuerreotype/docker-debian-artifacts/tree/dist-amd64/testing/slim)
  via [Docker](https://hub.docker.com/_/debian/).
- Binaries have supported
  [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29)
  options enabled.
- Binaries are using
  [SEH](https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH),
  except x86, which uses [DWARF](https://en.wikipedia.org/wiki/DWARF).
- We verify components using SHA-256 hashes and PGP signatures where provided.
- We build [reproducible](https://reproducible-builds.org/) binaries,
  producing the same hash given the same input sources and C compiler.
- Patching policy: No locally maintained patches. We may apply patches if
  already merged upstream or &mdash; for showstoppers &mdash; had them
  submitted with fair confidence of getting merged.
- We plan to switch the default TLS backend to BoringSSL. This fixes a
  long-standing [vulnerability](https://curl.se/docs/CVE-2019-5443.html). It
  also makes binaries 30% smaller. Downsides are no API/ABI guaranties, pthread
  dependence and missing TLS-SRP support.
- You can look up the correct distro hashes in lines starting with `SHA` in the
  [build log](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main).
- Packages created across host platforms do not have identical hashes.
  The reason for this is slightly different build options and toolchain
  builds/versions. Except `llvm-mingw` builds, which are reproducible across
  build hosts. ARM64 and all BoringSSL builds are like that by default.
- We code sign with a self-signed certificate, and intentionally not use
  trusted timestamps for reproducibility.

# Features

Default build with OpenSSL (QUIC [fork](https://github.com/quictls/openssl/)),
and [Schannel](https://docs.microsoft.com/windows/win32/com/schannel)
runtime-selectable option:
```
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe TLS-SRP UnixSockets zstd
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl -lbcrypt -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lzstd -lnghttp3 -lngtcp2
```
<details><summary>Alternate configurations with different footprints:</summary><p>

```
"big":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM PSL SPNEGO SSL SSPI threadsafe         UnixSockets zstd
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl          -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lzstd -lnghttp3 -lngtcp2 -lpsl -liconv -lunistring

"boringssl":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets zstd
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl          -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lzstd -lnghttp3 -lngtcp2

"noh3", HTTP/2:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2       HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe TLS-SRP UnixSockets zstd
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl -lbcrypt -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lzstd

"mini", Schannel, with OS-provided IDN support:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS        gsasl HSTS HTTP2                   IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl -lbcrypt

"micro", without libssh2 and libgsasl:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS              HSTS HTTP2                   IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2

"nano", HTTP/1.1:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp ws wss
Features:         AsynchDNS              HSTS                         IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32

"pico", HTTP/1.1-only:
Protocols:                                   http https
Features:         AsynchDNS              HSTS                             IPv6          Largefile libz                          SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32
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

THIS SOFTWARE (INCLUDING RESULTING BINARIES) IS PROVIDED "AS IS", WITHOUT
WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

Information in this document is subject to change without notice and does
not represent or imply any future commitment by the participants of the
project.

---
This document &copy;&nbsp;2014&ndash;present [Viktor Szakats](https://vsz.me/)<br>
[![Creative Commons Attribution-ShareAlike 4.0](https://raw.githubusercontent.com/curl/curl-for-win/main/cc-by-sa.svg?sanitize=1)](https://creativecommons.org/licenses/by-sa/4.0/)
