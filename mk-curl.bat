:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo off

set _NAM=curl

setlocal
pushd "%_NAM%"

:: Build

set ZLIB_PATH=../../zlib
set OPENSSL_PATH=../../openssl
set OPENSSL_INCLUDE=%OPENSSL_PATH%/include
set OPENSSL_LIBPATH=%OPENSSL_PATH%
set OPENSSL_LIBS=-lssl -lcrypto
set LIBSSH2_PATH=../../libssh2
if "%CPU%" == "win32" set ARCH=w32
if "%CPU%" == "win64" set ARCH=w64
set CURL_CFLAG_EXTRAS=-DCURL_STATICLIB -fno-ident
set CURL_LDFLAG_EXTRAS=-static-libgcc
rem   -flto -ffat-lto-objects

mingw32-make mingw32-clean
mingw32-make mingw32-ssh2-ssl-sspi-zlib-ldaps-ipv6

:: Create package

set _BAS=%_NAM%-%VER_CURL%-%CPU%-mingw
if "%APPVEYOR_REPO_BRANCH%" == "master" set _BAS=%_BAS%-t
if "%APPVEYOR_REPO_BRANCH%" == "master" set _REPOSUFF=-test
set _DST=%TEMP%\%_BAS%

:: Download CA bundle

if not exist "%~dp0\ca-bundle.crt" curl -fsS -L --proto-redir =https https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt -o "%~dp0\ca-bundle.crt"

xcopy /y /s /q docs\*.               "%_DST%\docs\*.txt"
xcopy /y /s /q docs\*.html           "%_DST%\docs\"
xcopy /y /s /q docs\libcurl\*.html   "%_DST%\docs\libcurl\"
xcopy /y /s /q include\curl\*.h      "%_DST%\include\curl\"
 copy /y       lib\mk-ca-bundle.pl   "%_DST%\"
 copy /y       lib\mk-ca-bundle.vbs  "%_DST%\"
 copy /y       CHANGES               "%_DST%\CHANGES.txt"
 copy /y       COPYING               "%_DST%\COPYING.txt"
 copy /y       README                "%_DST%\README.txt"
 copy /y       RELEASE-NOTES         "%_DST%\RELEASE-NOTES.txt"
xcopy /y /s    src\*.exe             "%_DST%\bin\"
xcopy /y /s    lib\*.dll             "%_DST%\bin\"
 copy /y       "%~dp0\ca-bundle.crt" "%_DST%\bin\curl-ca-bundle.crt"

if exist lib\*.a   xcopy /y /s lib\*.a   "%_DST%\lib\"
if exist lib\*.lib xcopy /y /s lib\*.lib "%_DST%\lib\"

unix2dos "%_DST%\*.txt"
unix2dos "%_DST%\docs\*.txt"

set _CDO=%CD%

pushd "%_DST%\.."
if exist "%_CDO%\%_BAS%.zip" del /f "%_CDO%\%_BAS%.zip"
7z a -bd -r -mx -tzip "%_CDO%\%_BAS%.zip" "%_BAS%\*" > nul
popd

rd /s /q "%TEMP%\%_BAS%"

curl -fsS -u "%BINTRAY_USER%:%BINTRAY_APIKEY%" -X PUT "https://api.bintray.com/content/%BINTRAY_USER%/generic/%_NAM%%_REPOSUFF%/%VER_CURL%/%_BAS%.zip?override=1&publish=1" --data-binary "@%_BAS%.zip"
for %%I in ("%_BAS%.zip") do echo %%~nxI: %%~zI bytes %%~tI
openssl dgst -sha256 "%_BAS%.zip"
openssl dgst -sha256 "%_BAS%.zip" >> ..\hashes.txt

popd
endlocal
