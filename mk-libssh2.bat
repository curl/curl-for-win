:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo off

setlocal
pushd libssh2

:: Build

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
mingw32-make clean
mingw32-make
popd

:: Create package

set _NAM=libssh2-%VER_LIBSSH2%-%CPU%-mingw
if "%APPVEYOR_REPO_BRANCH%" == "master" set _NAM=%_NAM%-t
set _DST=%TEMP%\%_NAM%

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

set _CDO=%CD%

pushd "%_DST%\.."
if exist "%_CDO%\%_NAM%.zip" del /f "%_CDO%\%_NAM%.zip"
7z a -bd -r -mx -tzip "%_CDO%\%_NAM%.zip" "%_NAM%\*" > nul

popd

rd /s /q "%TEMP%\%_NAM%"

curl -fsS -u "%BINTRAY_USER%:%BINTRAY_APIKEY%" -X PUT "https://api.bintray.com/content/vszakats/generic/libssh2-test/%VER_LIBSSH2%/%_NAM%.zip?override=1&publish=1" --data-binary "@%_NAM%.zip"
for %%I in ("%_NAM%.zip") do echo %%~nxI: %%~zI bytes %%~tI
openssl dgst -sha256 "%_NAM%.zip"
openssl dgst -sha256 "%_NAM%.zip" >> hashes.txt

popd
endlocal
