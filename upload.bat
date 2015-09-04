:: Copyright 2014-2015 Viktor Szakats (vszakats.net/harbour). See LICENSE.md.

@echo off

curl -fsS -u "%BINTRAY_USER%:%BINTRAY_APIKEY%" -X PUT "https://api.bintray.com/content/%BINTRAY_USER%/generic/%_NAM%%_REPOSUFF%/%_VER%/%_BAS%.zip?override=1&publish=1" --data-binary "@%_BAS%.zip"
for %%I in ("%_BAS%.zip") do echo %%~nxI: %%~zI bytes %%~tI
openssl dgst -sha256 "%_BAS%.zip"
openssl dgst -sha256 "%_BAS%.zip" >> ..\hashes.txt
