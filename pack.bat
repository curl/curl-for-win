:: Copyright 2014-2015 Viktor Szakats <https://github.com/vszakats>
:: See LICENSE.md

@echo off

set _CDO=%CD%

pushd "%_DST%\.."
if exist "%_CDO%\%_BAS%.7z" del /f "%_CDO%\%_BAS%.7z"
7z a -bd -r -mx "%_CDO%\%_BAS%.7z" "%_BAS%\*" > nul
popd

rd /s /q "%TEMP%\%_BAS%"
