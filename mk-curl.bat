:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo off

setlocal
pushd curl

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

if not exist "include\curl\curlver.h" (
   echo Error: Move this script to the source root directory.
   exit /b
)

set _NAM=curl-%VER_CURL%-%CPU%-mingw-t
set _DST=%TEMP%\%_NAM%

:: Download CA bundle
set _DL_URL=https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt
set _DL_DST=%~dp0\ca-bundle.crt

set _TMP=%TEMP%\_webdl.js
echo var http = new ActiveXObject(^"WinHttp.WinHttpRequest.5.1^");> "%_TMP%"
echo http.Open(^"GET^", ^"%_DL_URL%^", false);>> "%_TMP%"
echo http.Send();>> "%_TMP%"
echo if(http.Status() == 200) {>> "%_TMP%"
echo    var f = new ActiveXObject(^"ADODB.Stream^");>> "%_TMP%"
echo    f.type = 1; f.open(); f.write(http.responseBody);>> "%_TMP%"
echo    f.savetofile(^"%_DL_DST:\=\\%^", 2);>> "%_TMP%"
echo }>> "%_TMP%"
cscript "%_TMP%" //Nologo
del "%_TMP%"

xcopy /y /s /q docs\*.              "%_DST%\docs\*.txt"
xcopy /y /s /q docs\*.html          "%_DST%\docs\"
xcopy /y /s /q docs\libcurl\*.html  "%_DST%\docs\libcurl\"
xcopy /y /s /q include\curl\*.h     "%_DST%\include\curl\"
 copy /y       lib\mk-ca-bundle.pl  "%_DST%\"
 copy /y       lib\mk-ca-bundle.vbs "%_DST%\"
 copy /y       CHANGES              "%_DST%\CHANGES.txt"
 copy /y       COPYING              "%_DST%\COPYING.txt"
 copy /y       README               "%_DST%\README.txt"
 copy /y       RELEASE-NOTES        "%_DST%\RELEASE-NOTES.txt"
xcopy /y /s    src\*.exe            "%_DST%\bin\"
xcopy /y /s    lib\*.dll            "%_DST%\bin\"
 copy /y       ca-bundle.crt        "%_DST%\bin\curl-ca-bundle.crt"

if exist lib\*.a   xcopy /y /s lib\*.a   "%_DST%\lib\"
if exist lib\*.lib xcopy /y /s lib\*.lib "%_DST%\lib\"

unix2dos "%_DST%\*.txt"
unix2dos "%_DST%\docs\*.txt"

set _CDO=%CD%

pushd "%_DST%\.."
if exist "%_CDO%\%_NAM%.zip" del /f "%_CDO%\%_NAM%.zip"
rem zip -q -9 -X -r -o "%_CDO%\%_NAM%.zip" "%_NAM%" -i *
7z a -bd -r -mx -tzip "%_CDO%\%_NAM%.zip" "%_NAM%\*" > nul
popd

rd /s /q "%TEMP%\%_NAM%"

curl -u "%BINTRAY_USER%:%BINTRAY_APIKEY%" -X PUT "https://api.bintray.com/content/vszakats/generic/curl-test/%VER_CURL%/%_NAM%.zip?override=1&publish=1" --data-binary "@%_NAM%.zip"
for %%I in ("%_NAM%.zip") do echo %%~nxI: %%~zI bytes %%~tI
openssl dgst -sha256 "%_NAM%.zip"

popd
endlocal
