:: Copyright 2015 Viktor Szakats <https://github.com/vszakats>
:: See LICENSE.md

@echo off

set _NAM=%~n0
set _NAM=%_NAM:~3%
set _VER=%1
set _CPU=%2

setlocal
set _CDO=%CD%
pushd "%_NAM%"

:: Build

del /s *.o *.a *.lo *.la *.lai *.Plo *.pc >> nul 2>&1
if "%_CPU%" == "win32" set LDFLAGS=-m32
if "%_CPU%" == "win64" set LDFLAGS=-m64
set CFLAGS=%LDFLAGS% -U__STRICT_ANSI__ -DNGHTTP2_STATICLIB
set CXXFLAGS=%CFLAGS%
:: Open dummy file descriptor to fix './<script>: line <n>: 0: Bad file descriptor'
sh -c "exec 0</dev/null && ./configure --enable-lib-only '--prefix=%CD:\=/%'"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make install"

:: Make steps for determinism

if exist lib\*.a strip -p --enable-deterministic-archives -g lib\*.a

touch -c include/*.* -r ChangeLog
touch -c lib/*.*     -r ChangeLog

:: Create package

set _BAS=%_NAM%-%_VER%-%_CPU%-mingw
set _DST=%TEMP%\%_BAS%

xcopy /y /s include\*.*          "%_DST%\include\"
 copy /y    ChangeLog            "%_DST%\ChangeLog.txt"
 copy /y    AUTHORS              "%_DST%\AUTHORS.txt"
 copy /y    COPYING              "%_DST%\COPYING.txt"
 copy /y    README.rst           "%_DST%\README.rst"

if exist lib\*.a  xcopy /y    lib\*.a  "%_DST%\lib\"
if exist lib\*.la xcopy /y    lib\*.la "%_DST%\lib\"
if exist lib\*.pc xcopy /y /s lib\*.pc "%_DST%\lib\"

unix2dos -k %_DST:\=/%/*.txt
unix2dos -k %_DST:\=/%/*.rst

touch -c %_DST:\=/%/include/nghttp2 -r ChangeLog
touch -c %_DST:\=/%/include         -r ChangeLog
touch -c %_DST:\=/%/lib/pkgconfig   -r ChangeLog
touch -c %_DST:\=/%/lib             -r ChangeLog
touch -c %_DST:\=/%                 -r ChangeLog

call ..\pack.bat
call ..\upload.bat

popd
endlocal
