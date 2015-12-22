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
:: Open dummy file descriptor to fix './<script>: line <n>: 0: Bad file descriptor'
sh -c "exec 0</dev/null && ./configure '--prefix=%CD:\=/%'"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make"
sh -c "exec 0</dev/null && mingw32-make MAKE=C:/w/mingw64/bin/mingw32-make install"

:: Make steps for determinism

if exist .libs\*.a strip -p --enable-deterministic-archives -g .libs\*.a

touch -c .libs/*.a -r Changes

popd
endlocal
