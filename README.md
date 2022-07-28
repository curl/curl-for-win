[![License](https://raw.githubusercontent.com/curl/curl-for-win/main/MIT.svg?sanitize=1)](LICENSE.md)
[![Build status](https://ci.appveyor.com/api/projects/status/8yf6xjgq7u0cm013/branch/main?svg=true)](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main)

# Reproducible curl binaries for Windows

- ⚠ If you are using 32-bit (x86) curl-for-win builds, on the next curl
  release, 7.85.0, on 2022-08-31, we will drop support for Windows XP in
  these binaries, and they will require Vista.
  <br><br>
- We provide binary packages in `.zip` and `.tar.xz` formats,
  signed with PGP key:
  <br>[`002C 1689 65BA C220 2118  408B 4ED8 5DF9 BB3D 0DE8`](https://raw.githubusercontent.com/curl/curl-for-win/main/sign-pkg-public.asc)
- Standalone `curl.exe` and `libcurl.dll`.
  [Universal CRT](https://devblogs.microsoft.com/cppblog/introducing-the-universal-crt/)
  required. UCRT replaces `msvcrt.dll`, and it comes with Windows 10 and later.
  Back to Vista it came via Windows Update. XP needs v14.27.29114.0 of it,
  installed manually:
  [x86](https://download.visualstudio.microsoft.com/download/pr/56f631e5-4252-4f28-8ecc-257c7bf412b8/D305BAA965C9CD1B44EBCD53635EE9ECC6D85B54210E2764C8836F4E9DEFA345/VC_redist.x86.exe),
  [x64](https://download.visualstudio.microsoft.com/download/pr/722d59e4-0671-477e-b9b1-b8da7d4bd60b/591CBE3A269AFBCC025681B968A29CD191DF3C6204712CBDC9BA1CB632BA6068/VC_redist.x64.exe).
  [More](https://www.msys2.org/docs/environments/#msvcrt-vs-ucrt),
  [information](https://docs.microsoft.com/cpp/porting/upgrade-your-code-to-the-universal-crt),
  [here](https://docs.microsoft.com/cpp/windows/universal-crt-deployment).
- x64 binaries need Vista. x86 supports XP. We plan to bump it to Vista soon.
- Binary packages also contain all static libraries for curl and its
  dependencies.
- curl/libcurl have
  [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3) and
  [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support enabled.
  Detailed feature list [below](#features).
- Transparent builds, using open source code, and running them in
  [public](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main),
  with auditable [logs](#build-logs).
- Build environment is [`mingw-w64`](https://sourceforge.net/p/mingw-w64/)
  via [Debian](https://packages.debian.org/testing/mingw-w64),
  [Homebrew](https://formulae.brew.sh/formula/mingw-w64),
  [MSYS2](https://www.msys2.org/).
  [`llvm-mingw`](https://github.com/mstorsjo/llvm-mingw) for ARM64.
  C compiler is [LLVM/Clang](https://clang.llvm.org/).
- Binaries cross-built and published from Linux
  via [AppVeyor CI](https://www.appveyor.com/). Using reproducible OS image
  [`debian:testing-slim`](https://github.com/debuerreotype/docker-debian-artifacts/tree/dist-amd64/testing/slim)
  via [Docker](https://hub.docker.com/_/debian/).
- Binaries have supported
  [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29)
  options enabled.
- We verify components using SHA-256 hashes and PGP signatures where provided.
- Generated binaries are [reproducible](https://reproducible-builds.org/),
  meaning they produce the same hash given the same input sources and C
  compiler.
- Patching policy: No locally maintained patches. We apply patches locally if
  already merged upstream or &mdash; if necessary for a successful build
  &mdash; had them submitted upstream with fair confidence of getting accepted.
- We plan to switch the default TLS backend to BoringSSL. This fixes a
  long-standing [vulnerability](https://curl.se/docs/CVE-2019-5443.html). It
  also makes binaries 30% smaller. Downsides are no API/ABI guaranties, pthread
  dependence and missing TLS-SRP support.
- You can verify hashes by looking up the correct values in the build log.
  Watch for `main` branch, log lines starting with `SHA`:
    <https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main>
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
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe TLS-SRP UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl -lbcrypt -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lnghttp3 -lngtcp2
```
<details><summary>Alternate configurations with different footprints:</summary><p>

```
"big":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM PSL SPNEGO SSL SSPI threadsafe         UnixSockets zstd
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl          -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lnghttp3 -lngtcp2 -lpsl -liconv -lunistring -lzstd

"boringssl":
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl          -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon -lnghttp3 -lngtcp2

"noh3", HTTP/2:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2       HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM     SPNEGO SSL SSPI threadsafe TLS-SRP UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl -lbcrypt -lssl -lcrypto -lidn2 -lbrotlidec -lbrotlicommon

"mini", Schannel, with OS-provided IDN support:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS        gsasl HSTS HTTP2                   IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2 -lssh2 -lgsasl -lbcrypt

"micro", without libssh2 and libgsasl:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS              HSTS HTTP2                   IDN IPv6 Kerberos Largefile libz          NTLM     SPNEGO SSL SSPI threadsafe         UnixSockets
Libs: -lcurl -lz -lcrypt32 -lwldap32 -lnghttp2

"nano", HTTP/1.1:
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp          smb smbs smtp smtps telnet tftp
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
