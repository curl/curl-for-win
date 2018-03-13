[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)
[![Build Status](https://api.travis-ci.org/vszakats/curl-for-win.svg?branch=master)](https://travis-ci.org/vszakats/curl-for-win)
[![Build status](https://ci.appveyor.com/api/projects/status/87v0116m4re6j8di/branch/master?svg=true)](https://ci.appveyor.com/project/vszakats/curl-for-win/branch/master)

# Automated, reproducible, transparent, Windows builds for [curl](https://curl.haxx.se/), [nghttp2](https://nghttp2.org/), [brotli](https://github.com/google/brotli), [libssh2](https://libssh2.org/) and [OpenSSL 1.1](https://www.openssl.org/)

  - Packaging aims to follow popular binary releases found on the internet.
  - Both x86 and x64 packages are built using the same process.
  - Binary packages are downloadable in `.zip`, `.tar.xz` and `.7z` formats.<br>
    **Note that the `.7z` format is discontinued. Please update your download
    links accordingly.**<br>
    Please note that `.xz` and the resulting `.tar` file can also be
    extracted using 7-zip on Windows.
  - Standalone `curl.exe` (only [`msvcrt.dll`](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#MSVCRT.DLL.2C_MSVCPP.DLL_and_CRTDLL.DLL) is [required](https://blogs.msdn.microsoft.com/oldnewthing/20140411-00/?p=1273)).
  - curl/libcurl are built with [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2)
    support enabled.
  - curl/libcurl features enabled by default:
    <br>`dict file ftp ftps gopher http https imap imaps ldap ldaps pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp`
    <br>`AsynchDNS IDN IPv6 Largefile SSPI Kerberos SPNEGO NTLM SSL libz TLS-SRP HTTP2 HTTPS-proxy MultiSSL`
  - The build process is fully transparent by using publicly available
    open source code, C compiler, build scripts and running the
    build [in public](https://travis-ci.org/vszakats/curl-for-win/branches),
    with open, auditable [build logs](#live-build-logs).
  - C compiler toolchain is latest MinGW-w64 (non-multilib, x86 and x64)
    either via [Homebrew](https://brew.sh/) (on macOS),
    [APT](https://en.wikipedia.org/wiki/APT_(Debian)) (on Ubuntu via Docker) or
    [MSYS2](https://www.msys2.org/) (on Windows).
    C compiler is [GCC](https://gcc.gnu.org/) and optionally
    [LLVM/Clang](https://clang.llvm.org/) for projects supporting it.
  - Binaries are cross-built and published from macOS
    (via [Travis CI](https://travis-ci.org/)), using LLVM/Clang for curl,
    libssh2, nghttp2, c-ares, brotli and zlib, and GCC for others.
  - Binaries are built with supported [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29) options enabled.
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
  - Generated binaries are GPG signed with Bintray's [key pair](https://bintray.com/docs/usermanual/uploads/uploads_managinguploadedcontent.html#_signing_with_the_bintray_key):
    **[8756 C4F7 65C9 AC3C B6B8  5D62 379C E192 D401 AB61](https://pgp.mit.edu/pks/lookup?op=vindex&fingerprint=on&search=0x8756C4F765C9AC3CB6B85D62379CE192D401AB61)**
  - Patching policy: No locally maintained patches. Patches are only
    applied locally if already merged upstream or &mdash; in case it's
    necessary for a successful build &mdash; had them submitted upstream
    with fair confidence of getting accepted.
  - curl/libcurl are built in MultiSSL mode, with both OpenSSL and
    [WinSSL](https://en.wikipedia.org/wiki/Cryptographic_Service_Provider)
    available as SSL backends.
  - Optional support for
    [C-ares](https://c-ares.haxx.se/),
    [librtmp](https://rtmpdump.mplayerhq.hu/).
  - Generated binaries are uploaded to [VirusTotal](https://www.virustotal.com/).
  - If you need a download with a stable checksum, link to the penultimate
    version. Only the current latest versions are kept updated with newer
    dependencies.
  - To verify the correct checksum for the latest build, you can look up the
    correct ones in the build log as they are generated. Watch for `master`
    branch jobs `CPU=64` and `CPU=32`, log lines starting with `SHA256(`:
      <https://travis-ci.org/vszakats/curl-for-win/branches>
  - The build process is multi-platform and able to cross-build Windows
    executables from \*nix hosts (Linux and macOS tested.)
  - Packages created across different host platforms won't currently have
    identical hashes. The reason for this is the slightly different build
    options and versions of the `mingw-w64` and `binutils` tools.
  - Code signing is implemented but not enabled yet for reasons below:
    - There doesn't seem to exist a way to get _free_ code signing
      certificates, so only a self-signed certificate could be used, which is
      not very useful.
    - The portable tool `osslsigncode` used for signing
      [will always embed](https://sourceforge.net/p/osslsigncode/bugs/8/) the
      current timestamp
      ([Signing Time &ndash; OID 1.2.840.113549.1.9.5](https://oidref.com/1.2.840.113549.1.9.25))
      in the signature, which breaks reproducibility. More precisely, this is
      added by OpenSSL's PKCS #7 module unconditionally.
    - Trusted timestamp included in the signature breaks reproducibility. This
      is an optional feature, though it appears to be good practice to include
      it.

# Binary package downloads

  * [![Download](https://api.bintray.com/packages/vszakats/generic/curl/images/download.svg)](https://bintray.com/vszakats/generic/curl/_latestVersion) curl
  * [![Download](https://api.bintray.com/packages/vszakats/generic/openssl/images/download.svg)](https://bintray.com/vszakats/generic/openssl/_latestVersion) openSSL
  * [![Download](https://api.bintray.com/packages/vszakats/generic/libssh2/images/download.svg)](https://bintray.com/vszakats/generic/libssh2/_latestVersion) libssh2
  * [![Download](https://api.bintray.com/packages/vszakats/generic/nghttp2/images/download.svg)](https://bintray.com/vszakats/generic/nghttp2/_latestVersion) nghttp2
  * [![Download](https://api.bintray.com/packages/vszakats/generic/brotli/images/download.svg)](https://bintray.com/vszakats/generic/brotli/_latestVersion) brotli
  * [![Download](https://api.bintray.com/packages/vszakats/generic/zlib/images/download.svg)](https://bintray.com/vszakats/generic/zlib/_latestVersion) zlib

# Live build logs

  * <https://travis-ci.org/vszakats/curl-for-win>
    (for published binaries)
  * <https://ci.appveyor.com/project/vszakats/curl-for-win/branch/master>

# Guarantees and Liability

  THIS SOFTWARE (INCLUDING RESULTING BINARIES) IS PROVIDED "AS IS", WITHOUT
  WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
  WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
  USE OR OTHER DEALINGS IN THE SOFTWARE.

  Information in this document is subject to change without notice and does
  not represent or imply any future commitment by the participants of the
  project.

---
This document &copy;&nbsp;2014&ndash;present [Viktor Szakats](https://vszakats.net/)<br>
[![Creative Commons Attribution-ShareAlike 4.0](https://mirrors.creativecommons.org/presskit/buttons/80x15/svg/by-sa.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
