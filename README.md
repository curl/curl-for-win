[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)
[![Build status](https://ci.appveyor.com/api/projects/status/4bx4006pge6jbqch/branch/master?svg=true)](https://ci.appveyor.com/project/vsz/harbour-deps/branch/master)
&nbsp;&nbsp;&nbsp;&nbsp;
[![PayPal Donate](https://img.shields.io/badge/PayPal-Donate_Now-f8981d.svg?colorA=00457c)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2DZM6WAGRJWT6 "Donate Now")

# Automated, reproducible, transparent, Windows builds for [curl](https://curl.haxx.se/), [nghttp2](https://nghttp2.org/), [libssh2](https://libssh2.org) and [OpenSSL 1.1](https://www.openssl.org/)

  - Packaging aims to follow popular binary releases found on the internet.
  - Both x86 and x64 packages are built using the same process.
  - Standalone `curl.exe` (only [`msvcrt.dll`](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#MSVCRT.DLL.2C_MSVCPP.DLL_and_CRTDLL.DLL) is required).
  - curl/libcurl are built with [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support enabled.
  - curl/libcurl features enabled by default:<br>
    `dict file ftp ftps gopher http https imap imaps ldap ldaps pop3 pop3s rtsp scp sftp smtp smtps telnet tftp`<br>
    `AsynchDNS IDN IPv6 Largefile SSPI Kerberos SPNEGO NTLM SSL libz TLS-SRP HTTP2 HTTPS-proxy`
  - The build process is fully transparent by using publicly available
    open source code, C compiler, build scripts and running the
    build [in public](https://ci.appveyor.com/project/vsz/harbour-deps),
    with open, auditable [build logs](#live-build-logs).
  - C compiler toolchain is MinGW-w64 (non-multilib, x86 and x64) via MSYS2.
  - Binaries are built with supported [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29) options enabled.
  - Binaries are using [DWARF](https://en.wikipedia.org/wiki/DWARF) in x86 and
    [SEH](https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH)
    in x64 builds.
  - Components are verified using SHA-256 hashes and also GPG signatures where available.
  - Generated binaries are [reproducible](https://reproducible-builds.org), meaning
    they will have the same hash given the same input sources and C compiler.
  - Because MSYS2 is updated before each build, subsequent builds _may_ use
    different versions/builds of the compiler toolchain. This may result in
    different generated binaries given otherwise unchanged source code and
    configuration, sometimes thus breaking reproducibility. This trade-off was
    decided to be tolerable for more ideal binaries and allowing this project
    to automatically benefit from continuous C compiler updates.
  - Generated binaries are GPG signed with Bintray's [key pair](https://bintray.com/docs/usermanual/uploads/uploads_gpgsigning.html):
    **[8756 C4F7 65C9 AC3C B6B8  5D62 379C E192 D401 AB61](https://pgp.mit.edu/pks/lookup?op=vindex&fingerprint=on&search=0x8756C4F765C9AC3CB6B85D62379CE192D401AB61)**
  - Patching policy: No locally maintained patches. Patches are only
    applied locally if already merged upstream or &mdash; in case it's
    necessary for a successful build &mdash; had them submitted upstream
    with fair confidence of getting accepted.
  - Optional support for [libidn](https://www.gnu.org/software/libidn/), [C-ares](https://c-ares.haxx.se/), [librtmp](https://rtmpdump.mplayerhq.hu/) and for [WinSSL](https://en.wikipedia.org/wiki/Cryptographic_Service_Provider) as a fall-back backend.
  - Generated binaries are uploaded to [VirusTotal](https://www.virustotal.com/).
  - If you need a download with a stable checksum, link to the penultimate version.
    Only the current latest versions are kept updated with newer dependencies.
  - Code signing is implemented but not enabled yet for reasons below:
    - There doesn't seem to exist a way to get _free_ code signing certificates,
      so only a self-signed certificate could be used, which is not very useful.
    - The portable tool (`osslsigncode`) used for signing
      [will always embed](https://sourceforge.net/p/osslsigncode/bugs/8/) the
      current timestamp in the signature
      ([Signing Time &mdash; OID 1.2.840.113549.1.9.5](https://oidref.com/1.2.840.113549.1.9.25)),
      which breaks reproducibility. More precisely, this is added by OpenSSL's
      PKCS #7 module automatically.
    - Signed timestamp included in the signature breaks reproducibility. This
      is an optional feature, though it appears to be good practice to include
      it.

# Please donate to support maintaining these builds

  [![PayPal](https://www.paypalobjects.com/webstatic/i/logo/rebrand/ppcom.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2DZM6WAGRJWT6)

# Binary package downloads

  * curl: <https://bintray.com/vszakats/generic/curl>
  * nghttp2: <https://bintray.com/vszakats/generic/nghttp2>
  * libssh2: <https://bintray.com/vszakats/generic/libssh2>
  * OpenSSL: <https://bintray.com/vszakats/generic/openssl>

# Live build logs

  * <https://ci.appveyor.com/project/vsz/harbour-deps/branch/master>

---
This document &copy;&nbsp;2014&ndash;2017 Viktor Szakáts <https://github.com/vszakats><br />
[![Creative Commons Attribution-ShareAlike 4.0](https://rawgit.com/cc-icons/cc-icons/master/fonts/cc-icons-svg/small.by-sa.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
