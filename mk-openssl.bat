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

set MAKE=mingw32-make

if "%_CPU%" == "win32" set SHARED_RCFLAGS=-F pe-i386
if "%_CPU%" == "win64" set SHARED_RCFLAGS=-F pe-x86-64

del /s *.o *.a *.exe >> nul 2>&1
if "%_CPU%" == "win32" perl Configure mingw   shared no-unit-test no-ssl2 no-ssl3 no-rc5 no-idea no-dso "--prefix=%CD:\=/%"
:: Disable asm in 64-bit builds. It makes linking the static libs fail in LTO mode:
::   C:\Users\...\AppData\Local\Temp\ccUO3sBD.s: Assembler messages:
::   C:\Users\...\AppData\Local\Temp\ccUO3sBD.s:23710: Error: operand type mismatch for `div'
::   lto-wrapper.exe: fatal error: gcc.exe returned 1 exit status
::   compilation terminated.
::   C:/mingw/bin/../lib/gcc/x86_64-w64-mingw32/5.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: lto-wrapper failed
::   collect2.exe: error: ld returned 1 exit status
if "%_CPU%" == "win64" perl Configure mingw64 shared no-unit-test no-ssl2 no-ssl3 no-rc5 no-idea no-dso no-asm "--prefix=%CD:\=/%"
sh -c "mingw32-make depend"
sh -c "mingw32-make"

:: Make steps for determinism

if exist *.a   strip -p --enable-deterministic-archives -g *.a
if exist *.lib strip -p --enable-deterministic-archives -g *.lib

:: Strip debug info

strip -p -s apps\openssl.exe

python ..\peclean.py apps\openssl.exe
python ..\peclean.py apps\*.dll
if exist engines\*.dll python ..\peclean.py engines\*.dll

touch -c apps/openssl.exe    -r CHANGES
touch -c apps/*.dll          -r CHANGES
touch -c engines/*.dll       -r CHANGES
touch -c include/openssl/*.h -r CHANGES
touch -c *.a                 -r CHANGES
touch -c *.lib               -r CHANGES

:: Test run

apps\openssl.exe version

:: Create package

set _BAS=%_NAM%-%_VER%-%_CPU%-mingw
set _DST=%TEMP%\%_BAS%

xcopy /y /q    apps\openssl.exe "%_DST%\"
xcopy /y /q    apps\*.dll       "%_DST%\"
xcopy /y /q    engines\*.dll    "%_DST%\engines\"
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

unix2dos -k %_DST:\=/%/*.txt

touch -c %_DST:\=/%/engines         -r CHANGES
touch -c %_DST:\=/%/include/openssl -r CHANGES
touch -c %_DST:\=/%/include         -r CHANGES
touch -c %_DST:\=/%/lib             -r CHANGES
touch -c %_DST:\=/%                 -r CHANGES

call ..\pack.bat
call ..\upload.bat

popd
endlocal
