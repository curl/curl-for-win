:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo off

set _CDO=%CD%

pushd "%_DST%\.."
if exist "%_CDO%\%_BAS%.zip" del /f "%_CDO%\%_BAS%.zip"
7z a -bd -r -mx -tzip "%_CDO%\%_BAS%.zip" "%_BAS%\*" > nul
popd

rd /s /q "%TEMP%\%_BAS%"
