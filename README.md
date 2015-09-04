[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.txt)
[![Build status](https://ci.appveyor.com/api/projects/status/4bx4006pge6jbqch/branch/master?svg=true)](https://ci.appveyor.com/project/vsz/harbour-deps/branch/master)

# Automated Windows builds for OpenSSL, libssh2, cURL

- Packaging tries to follow other binary releases found on the Internet
- Static libraries are built with LTO option enabled (can still be linked in non-LTO mode)
- Both 32-bit and 64-bit packages are built using the same process
- Components are verified using SHA-256 hashes

---
This document Copyright &copy;&nbsp;2014&ndash;2015 Viktor Szakáts (vszakats.net/harbour)<br />
[![Creative Commons Attribution-ShareAlike 4.0](https://rawgit.com/cc-icons/cc-icons/master/fonts/cc-icons-svg/small.by-sa.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
