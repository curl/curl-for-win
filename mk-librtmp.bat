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

pushd ..
popd

set INC=-I../../openssl/include -I../../zlib
if "%_CPU%" == "win32" set XCFLAGS=-m32
if "%_CPU%" == "win64" set XCFLAGS=-m64
set XLDFLAGS=%XCFLAGS% "-L%_CDO%/openssl" "-L%_CDO%/zlib"
set XLDFLAGS=%XCFLAGS% "-L%_CDO%/openssl" "-L%_CDO%/zlib"
set LDFLAGS=%XLDFLAGS%
del /s *.o *.a *.dll *.so *.exe >> nul 2>&1
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
