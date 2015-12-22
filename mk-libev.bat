:: Copyright 2015 Viktor Szakats <https://github.com/vszakats>
:: See LICENSE.md

@echo off

set _NAM=%~n0
set _NAM=%_NAM:~3%
set _VER=%1
set _CPU=%2

setlocal
pushd "%_NAM%"

:: Build

del /s *.o *.a *.lo *.la *.lai *.Plo >> nul 2>&1
if "%_CPU%" == "win32" set LDFLAGS=-m32
if "%_CPU%" == "win64" set LDFLAGS=-m64
set CFLAGS=%LDFLAGS%
:: Open dummy file descriptor to fix './<script>: line <n>: 0: Bad file descriptor'
sh -c "exec 0</dev/null && ./configure '--prefix=%CD:\=/%'"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make install"

:: Make steps for determinism

if exist lib\*.a strip -p --enable-deterministic-archives -g lib\*.a

touch -c include/*.* -r Changes
touch -c lib/*.*     -r Changes

:: Create package

set _BAS=%_NAM%-%_VER%-%_CPU%-mingw
set _DST=%TEMP%\%_BAS%

xcopy /y /s include\*.*          "%_DST%\include\"
xcopy /y /s lib\*.*              "%_DST%\lib\"
 copy /y    Changes              "%_DST%\Changes.txt"
 copy /y    LICENSE              "%_DST%\LICENSE.txt"
 copy /y    README               "%_DST%\README.txt"

unix2dos -k %_DST:\=/%/*.txt

touch -c %_DST:\=/%/include -r Changes
touch -c %_DST:\=/%/lib     -r Changes
touch -c %_DST:\=/%         -r Changes

call ..\pack.bat
call ..\upload.bat

popd
endlocal
