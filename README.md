[![License](https://raw.githubusercontent.com/curl/curl-for-win/main/MIT.svg?sanitize=1)](LICENSE.md)
[![Build status](https://ci.appveyor.com/api/projects/status/8yf6xjgq7u0cm013/branch/main?svg=true)](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main)

# Automated, reproducible, transparent, Windows builds for curl

- Binary packages are downloadable in `.zip` and `.tar.xz` formats.<br>
  You can extract `.xz` files and the resulting `.tar` archive using
  [7-Zip](https://www.7-zip.org/).
- We sign binary packages with the PGP key:
  <br><https://raw.githubusercontent.com/curl/curl-for-win/main/sign-pkg-public.asc>
  <br>`002C 1689 65BA C220 2118  408B 4ED8 5DF9 BB3D 0DE8`
- Standalone `curl.exe` and `libcurl.dll`
  ([`msvcrt.dll`](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#MSVCRT.DLL,_MSVCP*.DLL_and_CRTDLL.DLL)
  is
  [required](https://devblogs.microsoft.com/oldnewthing/?p=1273)).
- Support for
  [Universal CRT](https://devblogs.microsoft.com/cppblog/introducing-the-universal-crt/).
  We plan to make this the default soon, replacing `msvcrt.dll`. The runtime
  comes with Windows 10 and later (including Server equivalents). For earlier
  versions it came via Windows Update, or
  [manual](https://support.microsoft.com/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c)
  install.
  [More](https://www.msys2.org/docs/environments/#msvcrt-vs-ucrt),
  [information](https://docs.microsoft.com/cpp/porting/upgrade-your-code-to-the-universal-crt),
  [here](https://docs.microsoft.com/cpp/windows/universal-crt-deployment).
- The binary package also contains the static library for curl and its
  dependencies.
- curl/libcurl have
  [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3) [EXPERIMENTAL]
  and
  [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support enabled.
- default builds, with the default TLS backend OpenSSL (QUIC fork) and
  [Schannel](https://docs.microsoft.com/windows/win32/com/schannel)
  as runtime-selectable option:
  - `Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp`
  - `Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM SPNEGO SSL SSPI (threadsafe) TLS-SRP UnixSockets`
  - Libraries: `-lcurl -lwldap32 -lcrypt32 -lz -lnghttp2 -lssh2 -lgsasl -lbcrypt -lssl -lcrypto -lidn2 -lbrotlidec-static -lbrotlicommon-static -lnghttp3 -lngtcp2`
- "noh3" builds, like the default, without HTTP/3:
  - `Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp`
  - `Features: alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM SPNEGO SSL SSPI (threadsafe) TLS-SRP UnixSockets`
  - Libraries: `-lcurl -lwldap32 -lcrypt32 -lz -lnghttp2 -lssh2 -lgsasl -lbcrypt -lssl -lcrypto -lidn2 -lbrotlidec-static -lbrotlicommon-static`
- "mini" builds, with the single TLS backend Schannel, and system IDN backend:
  - `Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp`
  - `Features: alt-svc AsynchDNS gsasl HSTS HTTP2 IDN IPv6 Kerberos Largefile libz NTLM SPNEGO SSL SSPI (threadsafe) UnixSockets`
  - Libraries: `-lcurl -lwldap32 -lcrypt32 -lz -lnghttp2 -lssh2 -lgsasl -lbcrypt`
- "micro" builds, without `libssh2` and `libgsasl`:
  - `Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp`
  - `Features: alt-svc AsynchDNS HSTS HTTP2 IDN IPv6 Kerberos Largefile libz NTLM SPNEGO SSL SSPI (threadsafe) UnixSockets`
  - Libraries: `-lcurl -lwldap32 -lcrypt32 -lz -lnghttp2`
- "nano" builds, with HTTP/1.1:
  - `Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp`
  - `Features: alt-svc AsynchDNS HSTS IDN IPv6 Kerberos Largefile libz NTLM SPNEGO SSL SSPI (threadsafe) UnixSockets`
  - Libraries: `-lcurl -lwldap32 -lcrypt32 -lz`
- The build process is fully transparent by using publicly available
  open source code, C compiler, build scripts and running the build
  [in public](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main),
  with open, auditable [build logs](#build-logs).
- C compiler toolchain is latest MinGW-w64 (non-multilib, x64 and x86)
  either via [Homebrew](https://brew.sh/) (on macOS),
  [APT](https://en.wikipedia.org/wiki/APT_(Debian)) (on Debian via Docker)
  or [MSYS2](https://www.msys2.org/).
  C compiler is [LLVM/Clang](https://clang.llvm.org/).
- Binaries are cross-built and published from Linux
  (via [AppVeyor CI](https://www.appveyor.com/)).
  <br>OS image used for the builds is
  [`debian:testing-slim`](https://github.com/debuerreotype/docker-debian-artifacts/tree/dist-amd64/testing/slim)
  (a [reproducible](https://github.com/debuerreotype/debuerreotype) image)
  via [Docker](https://hub.docker.com/_/debian/).
- Binaries have supported
  [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29)
  options enabled.
- Binaries are using [DWARF](https://en.wikipedia.org/wiki/DWARF) in x86 and
  [SEH](https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH)
  in x64 builds.
- Components are verified using SHA-256 hashes and also GPG signatures where
  available.
- Generated binaries are [reproducible](https://reproducible-builds.org/),
  meaning they will have the same hash given the same input sources and C
  compiler.
- Patching policy: No locally maintained patches. We apply patches
  locally if already merged upstream or &mdash; if necessary for
  a successful build &mdash; had them submitted upstream with fair
  confidence of getting accepted.
  <br>NOTE: As of 2021, there is a small local patch applied to the OpenSSL
  configure script, which fixes a bug which in turn is necessary to better
  mitigate a high-severity vulnerability
  ([CVE-2019-5443](https://curl.se/docs/CVE-2019-5443.html)), which still
  has an incomplete fix in the default OpenSSL builds for Windows. The
  OpenSSL team rejected both patches. Even though the patch is minor, we
  do not promise we will maintain them here for an indefinite time.
  Another option under consideration is to migrate to an OpenSSL
  alternative (e.g. LibreSSL, rustls or Schannel).
- Generated binaries are automatically uploaded to
  [VirusTotal](https://www.virustotal.com/).
- To verify the correct checksum for the latest build, you can look up the
  correct ones in the build log. Watch for `main` branch job `Image: Ubuntu`,
  log lines starting with `SHA256(` or `SHA512(`:
    <https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main>
- The build process is multi-platform and able to cross-build Windows
  executables from \*nix hosts (Linux and macOS tested.)
- Packages created across different host platforms will not have identical
  hashes. The reason for this is the slightly different build options and
  versions of the `mingw-w64` and `binutils` tools.
- Code signing uses a self-signed certificate. The signature intentionally
  omits a trusted timestamp for reproducibility.

# Official binary downloads

* Latest version:
  <br><https://curl.se/windows/>
* Latest version direct links:
  <br><https://curl.se/windows/curl-win32-latest.zip>
  <br><https://curl.se/windows/curl-win64-latest.zip>
* Specific versions (back to 7.80.0):<br>
  `https://curl.se/windows/dl-<curl-version>[_<build-number>]/`
  <br>Examples:
  <br><https://curl.se/windows/dl-7.80.0/>
  <br><https://curl.se/windows/dl-7.80.0_1/>

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
