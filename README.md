[![License](https://raw.githubusercontent.com/curl/curl-for-win/main/MIT.svg?sanitize=1)](LICENSE.md)
[![Build status](https://ci.appveyor.com/api/projects/status/8yf6xjgq7u0cm013/branch/main?svg=true)](https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main)

# Automated, reproducible, transparent, Windows builds for [curl](https://curl.se/) and dependencies

  - Packaging aims to follow popular binary releases found on the internet.
  - Both x64 and x86 packages are built using the same process.
  - Binary packages are downloadable in `.zip` and `.tar.xz` formats.<br>
    `.xz` files and the resulting `.tar` archive can be extracted using
    [7-Zip](https://www.7-zip.org/).
  - Binary packages are signed with PGP key [EXPERIMENTAL]:
    <br><https://raw.githubusercontent.com/curl/curl-for-win/main/sign-pkg-public.asc>
    <br>`002C 1689 65BA C220 2118  408B 4ED8 5DF9 BB3D 0DE8`
  - Standalone `curl.exe` and `libcurl.dll` (only
    [`msvcrt.dll`](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#MSVCRT.DLL,_MSVCP*.DLL_and_CRTDLL.DLL)
    is
    [required](https://devblogs.microsoft.com/oldnewthing/?p=1273)).
  - curl/libcurl are built with [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2)
    support enabled.
  - curl/libcurl features enabled by default (`{upcoming}`):
    <br>`dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp`
    <br>`alt-svc AsynchDNS brotli gsasl HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz MultiSSL NTLM SPNEGO SSL SSPI TLS-SRP UnixSockets zstd`
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
    <br>Exact OS image used for the builds is
    [`debian:testing`](https://github.com/debuerreotype/docker-debian-artifacts/tree/dist-amd64/testing)
    (a [reproducible](https://github.com/debuerreotype/debuerreotype) image)
    via [Docker](https://hub.docker.com/_/debian/).
  - Binaries are built with supported
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
  - Because the build environment is updated before each build, subsequent
    builds _may_ use different versions/builds of the compiler toolchain.
    This may result in different generated binaries given otherwise unchanged
    source code and configuration, sometimes thus breaking reproducibility.
    This trade-off was decided to be tolerable for more ideal binaries and
    allowing this project to automatically benefit from continuous C compiler
    updates.
  - Patching policy: No locally maintained patches. Patches are only
    applied locally if already merged upstream or &mdash; in case it is
    necessary for a successful build &mdash; had them submitted upstream with
    fair confidence of getting accepted.
  - curl/libcurl are built in MultiSSL mode, with both OpenSSL and
    [Schannel](https://docs.microsoft.com/windows/win32/com/schannel)
    available as SSL backends.
  - Optional support for
    [c-ares](https://c-ares.haxx.se/).
  - Generated binaries are uploaded to [VirusTotal](https://www.virustotal.com/).
  - To verify the correct checksum for the latest build, you can look up the
    correct ones in the build log as they are generated. Watch for `main`
    branch job `Image: Ubuntu`, log lines starting with
    `SHA256(` or `SHA512(`:
      <https://ci.appveyor.com/project/curlorg/curl-for-win/branch/main>
  - The build process is multi-platform and able to cross-build Windows
    executables from \*nix hosts (Linux and macOS tested.)
  - Packages created across different host platforms will not currently have
    identical hashes. The reason for this is the slightly different build
    options and versions of the `mingw-w64` and `binutils` tools.
  - Code signing is implemented and enabled with a self-signed certificate.
    The signature intentionally omits a trusted timestamp to retain
    reproducibility.

# Binary package download

  * Official page, latest version:<br>
    <https://curl.se/windows/>
  * Official page, specific versions (back to 7.66.0):<br>
    `https://curl.se/windows/dl-<curl-version>[_<build-number>]/`
    <br>Examples:
    <br><https://curl.se/windows/dl-7.77.0/>
    <br><https://curl.se/windows/dl-7.77.0_1/>

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
