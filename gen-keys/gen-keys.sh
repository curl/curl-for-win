#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

[ -d workdir ] && rm -r -f workdir
mkdir -m 700 workdir
(
  cd workdir

  # 1. code signing certificate and key

  name='curl-for-win'
  year='2024'
  # TODO: Switch to ECC once OpenSSL got support for deterministic ECDSA nonces
  ../mk-cert-code.sh "${name}" "${year}" rsa

  cp -p "${name}_${year}-ca-cert.pem"  ../curl-for-win-ca-cert.pem
  cp -p "${name}_${year}-code.p12.asc" ../sign-code.p12.asc

  # 2. GPG package signing key

  name='curl-for-win-release-test'
  mail="${name}@localhost"
  ../mk-gpg-sign.sh '' "${name}" "${mail}"

  cp -p "${mail}-sign-public.asc"      ../sign-pkg-public.asc
  cp -p "${mail}-sign-private_gpg.asc" ../sign-pkg.gpg.asc

  # 3. package blob cosign key pair

  name='curl-for-win'
  year='2025'
  ../mk-cosign.sh "${name}" "${year}"

  cp -p cosign.pub     ../cosign.pub.asc
  cp -p cosign.key.asc ../cosign.key.asc

  # 4. SSH deploy key

  ../mk-ssh-curl-for-win.sh

  mv deploy.key.asc ..
)
