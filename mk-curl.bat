:: Copyright 2014-2015 Viktor Szakats <https://github.com/vszakats>
:: See LICENSE.md

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
set OPENSSL_INCLUDE=%OPENSSL_PATH%/include
set OPENSSL_LIBPATH=%OPENSSL_PATH%
set OPENSSL_LIBS=-lssl -lcrypto
set LIBSSH2_PATH=../../libssh2
if "%_CPU%" == "win32" set ARCH=w32
if "%_CPU%" == "win64" set ARCH=w64
set CURL_CFLAG_EXTRAS=-DCURL_STATICLIB -fno-ident
set CURL_LDFLAG_EXTRAS=-static-libgcc

mingw32-make mingw32-clean
mingw32-make mingw32-ssh2-ssl-sspi-zlib-ldaps-ipv6

:: Create package

set _BAS=%_NAM%-%_VER%-%_CPU%-mingw
if not "%APPVEYOR_REPO_BRANCH%" == "master" set _BAS=%_BAS%-test
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

call ..\pack.bat
call ..\upload.bat

popd
endlocal
