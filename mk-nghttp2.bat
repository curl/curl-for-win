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

set CFLAGS=-U__STRICT_ANSI__ -I"%_CDO:\=/%/libev" -L"%_CDO:\=/%/libev/.libs"
set CXXFLAGS=%CFLAGS%
:: Open dummy file descriptor to fix './<script>: line <n>: 0: Bad file descriptor'
sh -c "exec 0</dev/null && ./configure '--prefix=%CD:\=/%'"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make install"

:: Make steps for determinism

if exist lib\.libs\*.a strip -p --enable-deterministic-archives -g lib\.libs\*.a

touch -c lib/.libs/*.a -r ChangeLog

popd
endlocal
