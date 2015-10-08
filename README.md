[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)
[![Build status](https://ci.appveyor.com/api/projects/status/4bx4006pge6jbqch/branch/master?svg=true)](https://ci.appveyor.com/project/vsz/harbour-deps/branch/master)

# Automated, reproducible, Windows builds for cURL, libssh2, OpenSSL

  - Packaging tries to follow other binary releases found on the Internet
  - Static libraries are built with LTO option enabled (can be linked in non-LTO mode as well)
  - Both 32-bit and 64-bit packages are built using the same process
  - Components are verified using SHA-256 hashes
  - Generated binaries are reproducible, meaning they will have the same
    hash given the same input sources and C compiler. Because LTO mode
    doesn't support reproducibility out of the box (as of GCC 5.2), the
    `-frandom-seed=` workaround is used (with a fixed value) to resolved
    this while building OpenSSL. See more on the issue here:

       * <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66305>
       * <https://reproducible.debian.net/issues/unstable/randomness_in_fat_lto_objects_issue.html>

# Please donate to support maintaining these builds

  - [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPSZQYKXMQJYG)

---
This document Copyright &copy;&nbsp;2014&ndash;2015 Viktor Szakáts <https://github.com/vszakats><br />
[![Creative Commons Attribution-ShareAlike 4.0](https://rawgit.com/cc-icons/cc-icons/master/fonts/cc-icons-svg/small.by-sa.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
