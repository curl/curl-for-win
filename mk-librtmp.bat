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

set INC=-I../../openssl/include
if "%_CPU%" == "win32" set XCFLAGS=-m32
if "%_CPU%" == "win64" set XCFLAGS=-m64
if "%_CPU%" == "win32" set XLDFLAGS=-m32 -L../../openssl/lib
if "%_CPU%" == "win64" set XLDFLAGS=-m64 -L../../openssl/lib
set LDFLAGS=%XLDFLAGS%
mingw32-make SYS=mingw SODEF_yes=

:: Make steps for determinism

if exist librtmp\*.a   strip -p --enable-deterministic-archives -g librtmp\*.a
if exist librtmp\*.lib strip -p --enable-deterministic-archives -g librtmp\*.lib

python ..\peclean.py *.exe
python ..\peclean.py librtmp\*.dll

touch -c librtmp/*.exe -r ChangeLog
touch -c librtmp/*.dll -r ChangeLog
touch -c librtmp/*.a   -r ChangeLog
touch -c librtmp/*.lib -r ChangeLog

popd
endlocal
