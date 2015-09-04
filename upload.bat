:: Copyright 2014-2015 Viktor Szakats <https://github.com/vszakats>
:: See LICENSE.md

@echo off

if     "%APPVEYOR_REPO_BRANCH%" == "master" set _SUF=
if not "%APPVEYOR_REPO_BRANCH%" == "master" set _SUF=-test

curl -fsS -u "%BINTRAY_USER%:%BINTRAY_APIKEY%" -X PUT "https://api.bintray.com/content/%BINTRAY_USER%/generic/%_NAM%/%_VER%%_SUF%/%_BAS%.7z?override=1&publish=1" --data-binary "@%_BAS%.7z"
for %%I in ("%_BAS%.7z") do echo %%~nxI: %%~zI bytes %%~tI
openssl dgst -sha256 "%_BAS%.7z"
openssl dgst -sha256 "%_BAS%.7z" >> ..\hashes.txt
