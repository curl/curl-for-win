:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo on

setlocal
pushd libssh2

set ZLIB_PATH=../../zlib
set OPENSSL_PATH=../../openssl
set OPENSSL_LIBPATH=%OPENSSL_PATH%
set OPENSSL_LIBS_DYN=crypto.dll ssl.dll
if "%CPU%" == "win32" set ARCH=w32
if "%CPU%" == "win64" set ARCH=w64
set LIBSSH2_CFLAG_EXTRAS=-fno-ident
rem -flto -ffat-lto-objects
set LIBSSH2_LDFLAG_EXTRAS=-static-libgcc

pushd win32

dos2unix ..\..\libssh2.diff
patch -p0 -i ..\..\libssh2.diff

mingw32-make clean
mingw32-make

popd

popd
endlocal
