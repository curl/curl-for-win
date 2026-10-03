#!/usr/bin/env bash

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd -- "$(dirname "${0}")"/../..

echo '::group::versions'
cosign version
minisign -v
ssh -V
gpg --version
echo '::endgroup::'

dir="$(mktemp -d)"; export GNUPGHOME="${dir}"

gpg --import sign-pkg-public.asc

for suffix in \
  win64-mingw.zip \
  win64-mingw.tar.xz \
  win64a-mingw.zip \
  win64-mingw.tar.xz \
; do

  url="$(curl --disable --fail --silent --show-error --connect-timeout 15 --max-time 60 --retry 3 --retry-connrefused \
    --location "https://curl.se/windows/latest.cgi?p=${suffix}" --output /dev/null --write-out '%{url_effective}')"

  echo "--- Downloading ${url}"
  rm -f _pkg.bin*
  curl --disable --fail --silent --show-error --connect-timeout 15 --max-time 60 --retry 3 --retry-connrefused \
    --output _pkg.bin          "${url}" \
    --output _pkg.bin.asc      "${url}.asc" \
    --output _pkg.bin.minisig  "${url}.minisig" \
    --output _pkg.bin.sigstore "${url}.sigstore" \
    --output _pkg.bin.sig      "${url}.sig" \
    --output _pkg.bin.txt      "${url}.txt"

  echo "--- Verifying ${url}"
  echo '--- cosign ---'
  cosign verify-blob --key cosign.pub.asc --bundle _pkg.bin.sigstore _pkg.bin
  echo '--- minisign ---'
  minisign -Vp minisign.pub -m _pkg.bin
  minisign -VP RWQcXBEFq5MO2MDhlrz30eklTuapCJXgMYBo3WDnlugoumiHsewGfvfK -m _pkg.bin
  echo '--- SSH ---'
  ssh-keygen -Y verify -n file -f id-curl-for-win-sign.id -I id-curl-for-win-sign -s _pkg.bin.sig < _pkg.bin
  echo '--- PGP ---'
  gpg --batch --keyserver-options timeout=15 --display-charset utf-8 --keyid-format 0xlong --verify-options show-primary-uid-only \
    --verify _pkg.bin.asc _pkg.bin 2>&1
  echo '--- SHA-256 ---'
  sed "s|(.*)|(_pkg.bin)|" _pkg.bin.txt | sha256sum -c -
  echo '---'
  rm -f _pkg.bin*
done

rm -r -f -- "${dir}"; unset GNUPGHOME
