:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo off

set _NAM=%~n0
set _NAM=%_NAM:~3%
set _VER=%1
set _CPU=%2

setlocal
pushd "%_NAM%"

:: Build

set ZLIB_PATH=../../zlib
set OPENSSL_PATH=../../openssl
set OPENSSL_LIBPATH=%OPENSSL_PATH%
set OPENSSL_LIBS_DYN=crypto.dll ssl.dll
if "%_CPU%" == "win32" set ARCH=w32
if "%_CPU%" == "win64" set ARCH=w64
set LIBSSH2_CFLAG_EXTRAS=-fno-ident
set LIBSSH2_LDFLAG_EXTRAS=-static-libgcc

pushd win32
mingw32-make clean
mingw32-make
popd

:: Create package

set _BAS=%_NAM%-%_VER%-%_CPU%-mingw
if not "%APPVEYOR_REPO_BRANCH%" == "master" set _BAS=%_BAS%-t
if not "%APPVEYOR_REPO_BRANCH%" == "master" set _REPOSUFF=-test
set _DST=%TEMP%\%_BAS%

xcopy /y /s /q docs\*.              "%_DST%\docs\*.txt"
xcopy /y /s /q include\*.*          "%_DST%\include\"
 copy /y       NEWS                 "%_DST%\NEWS.txt"
 copy /y       COPYING              "%_DST%\COPYING.txt"
 copy /y       README               "%_DST%\README.txt"
 copy /y       RELEASE-NOTES        "%_DST%\RELEASE-NOTES.txt"
xcopy /y /s    win32\*.dll          "%_DST%\bin\"

if exist win32\*.a   xcopy /y /s win32\*.a   "%_DST%\lib\"
if exist win32\*.lib xcopy /y /s win32\*.lib "%_DST%\lib\"

unix2dos "%_DST%\*.txt"
unix2dos "%_DST%\docs\*.txt"

call ..\pack.bat
call ..\upload.bat

popd
endlocal
