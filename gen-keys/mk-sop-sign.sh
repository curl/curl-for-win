#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-16

# Requires:
#   brew install hopenpgp-tools optipng qrencode scour
#
# hop (hopenpgp-tools) 0.25.8+

master="${1:-release-test@localhost-sign}"

install -m 600 /dev/null "${master}.password"; pwgen --secure 42 1 >> "${master}.password"

hop generate-key --signing-only --with-key-password "${master}.password" '' > "${master}-private.asc"
hop dearmor < "${master}-private.asc" | tee "${master}-private.pgp" | hot dump > "${master}-private.asc.txt"
hop extract-cert < "${master}-private.asc" > "${master}-public.asc"
hop dearmor < "${master}-public.asc" | hot dump > "${master}-public.asc.txt"

qrencode --type png --output "${master}-public-qr.png" < "${master}-public.asc"
optipng -silent -preserve -fix -strip all -o3 "${master}-public-qr.png"
qrencode --type svg --inline --svg-path --rle < "${master}-public.asc" | \
  scour --strip-xml-prolog --enable-comment-stripping --enable-id-stripping --enable-viewboxing --remove-metadata > "${master}-public-qr.svg"

# paperkey --secret-key "${master}-private.gpg" --output "${master}-private.gpg.paperkey.txt"

# Encrypt private key once again, for distribution (ASCII, binary)
age-keygen  -pq --output="${master}-private.pgp.age.key"
age --encrypt --identity="${master}-private.pgp.age.key" --armor "${master}-private.pgp" > "${master}-private.pgp.age.asc"

#hop sign --with-key-password "${master}.password" "${master}-private.asc" < curl-8.21.0_7-win64-mingw.zip > curl-8.21.0_7-win64-mingw.zip.asce
#hop verify "${master}-private.pgp" curl-8.21.0_7-win64-mingw.zip.asce < curl-8.21.0_7-win64-mingw.zip
