:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo on

setlocal
pushd openssl

:: local patches
sed -e "s/-march=i486 -Wall::-D_MT:MINGW32:-lws2_32/-march=i686 -mtune=generic -m32 -fno-ident -flto -ffat-lto-objects -static-libgcc -Wall::-D_MT:MINGW32:-lws2_32/g" -i Configure
sed -e "s/-DWIN32_LEAN_AND_MEAN -DUNICODE/-DWIN32_LEAN_AND_MEAN -DOPENSSL_NO_GOST -m64 -fno-ident -flto -ffat-lto-objects -static-libgcc -DUNICODE/g" -i Configure
sed -e "s/windres -o rc.o/windres $(SHARED_RCFLAGS) -o rc.o/g" -i Makefile.shared

if "%CPU%" == "win32" set SHARED_RCFLAGS=-F pe-i386
if "%CPU%" == "win64" set SHARED_RCFLAGS=-F pe-x86-64

del /s *.o *.a *.exe >> nul 2>&1
if "%CPU%" == "win32" sh -c perl Configure mingw   shared no-unit-test no-ssl2 no-ssl3 no-idea no-hw no-dso no-sse2 --prefix=C:/w/openssl
if "%CPU%" == "win64" sh -c perl Configure mingw64 shared no-unit-test no-ssl2 no-ssl3 no-idea no-hw no-dso no-asm  --prefix=C:/w/openssl
sh -c mingw32-make depend
sh -c mingw32-make

if not exist "include\openssl\opensslv.h" (
   echo Error: Move this script to the OpenSSL source root directory.
   exit /b
)

set _NAM=openssl-%VER_OPENSSL%-%CPU%-mingw
set _DST=%TEMP%\%_NAM%

xcopy /y /q    apps\openssl.exe "%_DST%\"
xcopy /y /q    apps\*.dll       "%_DST%\"
rem xcopy /y /q    engines\*.dll    "%_DST%\"
 copy /y       apps\openssl.cnf "%_DST%\openssl.cfg"
xcopy /y /s /q include\*.*      "%_DST%\include\"
xcopy /y /q    ms\applink.c     "%_DST%\include\openssl\"
 copy /y       CHANGES          "%_DST%\CHANGES.txt"
 copy /y       LICENSE          "%_DST%\LICENSE.txt"
 copy /y       README           "%_DST%\README.txt"
 copy /y       FAQ              "%_DST%\FAQ.txt"
 copy /y       NEWS             "%_DST%\NEWS.txt"

if exist *.a   xcopy /y /s *.a   "%_DST%\lib\"
if exist *.lib xcopy /y /s *.lib "%_DST%\lib\"

unix2dos "%_DST%\*.txt"

set _CDO=%CD%

pushd "%_DST%\.."
if exist "%_CDO%\%_NAM%.zip" del /f "%_CDO%\%_NAM%.zip"
rem zip -q -9 -X -r -o "%_CDO%\%_NAM%.zip" "%_NAM%" -i *
7z a -bd -r -mx -tzip "%_CDO%\%_NAM%.zip" "%_NAM%\*"

popd

rd /s /q "%TEMP%\%_NAM%"

:: curl -u "%BINTRAY_USER%:%BINTRAY_APIKEY%" -X PUT "https://api.bintray.com/content/vszakats/generic/openssl/%VER_OPENSSL%/%_NAM%.zip?override=1&publish=1" --data-binary "@%_NAM%.zip"
for %%I in ("%_NAM%.zip") do echo %%~nxI: %%~zI bytes %%~tI
openssl dgst -sha256 "%_NAM%.zip"

popd
endlocal
