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

# Do not put '-I' or '-L' in double quotes. It means these
# must be built on a path that does not contain spaces.
set CFLAGS=-U__STRICT_ANSI__ -I%_CDO:\=/%/libev -L%_CDO:\=/%/libev/.libs
set CXXFLAGS=%CFLAGS%
sh -c "./Configure"
mingw32-make

:: Make steps for determinism

if exist lib\.libs\*.a strip -p --enable-deterministic-archives -g lib\.libs\*.a

touch -c lib/.libs/*.a -r ChangeLog

popd
endlocal
