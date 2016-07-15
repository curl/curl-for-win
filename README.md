[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)
[![Build status](https://ci.appveyor.com/api/projects/status/4bx4006pge6jbqch/branch/master?svg=true)](https://ci.appveyor.com/project/vsz/harbour-deps/branch/master)
&nbsp;&nbsp;&nbsp;&nbsp;
[![PayPal Donate](https://img.shields.io/badge/PayPal-donate-f8981D.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2DZM6WAGRJWT6)

# Automated, reproducible, transparent, Windows builds for [cURL](https://curl.haxx.se/), [nghttp2](https://nghttp2.org/), [libssh2](https://libssh2.org), [OpenSSL](https://www.openssl.org/) and [LibreSSL](http://www.libressl.org/)

  - Packaging aims to follow popular binary releases found on the internet.
  - Both x86 and x64 packages are built using the same process.
  - Standalone `curl.exe` (only [`msvcrt.dll`](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#MSVCRT.DLL.2C_MSVCPP.DLL_and_CRTDLL.DLL) is required).
  - curl/libcurl are built with [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) support enabled.
  - The build process is fully transparent by using publicly available
    open source code, C compiler, build scripts and running the
    build [in public](https://ci.appveyor.com/project/vsz/harbour-deps),
    with open, auditable [build logs](#live-build-logs).
  - Binaries are built with supported [hardening](https://en.wikipedia.org/wiki/Hardening_%28computing%29) options enabled.
  - Binaries are currently using [SJLJ](https://stackoverflow.com/a/15685229/1732433) exception handling.
    (steps to migrate to [DWARF](https://en.wikipedia.org/wiki/DWARF)/[SEH](https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH) are underway)
  - Components are verified using SHA-256 hashes and also GPG signatures where available.
  - Generated binaries are [reproducible](https://reproducible-builds.org), meaning
    they will have the same hash given the same input sources and C compiler.
  - Generated binaries are GPG signed with Bintray's [key pair](https://bintray.com/docs/usermanual/uploads/uploads_gpgsigning.html):
    **[8756 C4F7 65C9 AC3C B6B8  5D62 379C E192 D401 AB61](https://pgp.mit.edu/pks/lookup?op=vindex&fingerprint=on&search=0x8756C4F765C9AC3CB6B85D62379CE192D401AB61)**
  - Patching policy: No locally maintained patches. Patches are only
    applied locally if already merged upstream or &mdash; in case it's
    necessary for a successful build &mdash; had them submitted upstream
    with fair confidence of getting accepted.
  - Optional support for [libidn](https://www.gnu.org/software/libidn/), [C-ares](http://c-ares.haxx.se), [librtmp](https://rtmpdump.mplayerhq.hu) and for [WinSSL](https://en.wikipedia.org/wiki/Cryptographic_Service_Provider) as a fall-back backend.
  - Generated binaries are uploaded to [VirusTotal](https://www.virustotal.com/).

# Please donate to support maintaining these builds

  [![PayPal](https://www.paypalobjects.com/webstatic/i/logo/rebrand/ppcom.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=2DZM6WAGRJWT6)

# Binary package downloads

  * cURL: <https://bintray.com/vszakats/generic/curl>
  * nghttp2: <https://bintray.com/vszakats/generic/nghttp2>
  * libssh2: <https://bintray.com/vszakats/generic/libssh2>
  * LibreSSL: <https://bintray.com/vszakats/generic/libressl>
  * OpenSSL: <https://bintray.com/vszakats/generic/openssl>

# Live build logs

  * <https://ci.appveyor.com/project/vsz/harbour-deps/branch/master>
  * <https://ci.appveyor.com/project/vsz/harbour-deps/branch/master-libressl>

---
This document Copyright &copy;&nbsp;2014&ndash;2016 Viktor Szakáts <https://github.com/vszakats><br />
[![Creative Commons Attribution-ShareAlike 4.0](https://rawgit.com/cc-icons/cc-icons/master/fonts/cc-icons-svg/small.by-sa.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
