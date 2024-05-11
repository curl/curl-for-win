#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Requires:
#   brew install gnupg pgpdump

# Redirect stdout securely to non-world-readable files
privout() {
  o="$1"; rm -f "$o"; install -m 600 /dev/null "$o"; shift
  (
    "$@"
  ) >> "$o"
}

case "$(uname)" in
  *Darwin*)
    MY_GPG='/usr/local/opt/gnupg/bin/gpg';;
  *)
    MY_GPG='gpg';;
esac

my_gpg() {
  "${MY_GPG}" --full-timestrings "$@"
}

dir="$(mktemp -d)"; export GNUPGHOME="${dir}"

if [ -n "${1:-}${2:-}${3:-}" ]; then
  base="$1"
  name="$2"
  mail="$3"
else
  base=''
  name='release-test'
  mail='release-test@localhost'
fi
usage='sign'
master="${base}${mail}-${usage}"

pass="$(openssl rand 32 | base58)"; readonly pass
privout "${master}.password" printf '%s' "${pass}"

# FIXME:
# Private keys are stored and exported using obsolete SHA1 and less-secure
# AES128, and no way to override that:
#   "iter+salt S2K, algo: 7 (AES128), SHA1 protection, hash: 2"
#   https://dev.gnupg.org/T1800 (open since 2014-12-30)
#   https://lists.gnupg.org/pipermail/gnupg-users/2017-January/057506.html
#   https://security.stackexchange.com/questions/119245/how-does-gnupg-encrypt-secret-keys
# Remains a problem with the v5 storage format introduced in gpg 2.3.0.

# infinite expiry date: 0
# default value: default
my_gpg --verbose \
  --batch --yes --no-tty \
  --keyid-format 0xlong \
  --s2k-cipher-algo aes256 \
  --s2k-digest-algo sha512 \
  --cert-digest-algo sha512 \
  --generate-key - << EOF 2>&1 | grep -a -F 'revocation certificate' | grep -a -o -m 1 -E '[A-F0-9]{40,}' > "${master}-id.txt"
key-type: EDDSA
key-curve: Ed25519
key-usage: ${usage}
name-real: ${name}
#name-comment: my comment
name-email: ${mail}
expire-date: 10y
passphrase: ${pass}
%commit
%echo ! Done.
EOF

fp="$(cat "${master}-id.txt")"; rm -f "${master}-id.txt"
echo "MY_GPG_SIGN_KEY=${fp}"

# Save the automatically generated revocation certificate
cp -p "${GNUPGHOME}/openpgp-revocs.d/${fp}.rev" "${master}-revocation.asc"

qrencode --type png "OPENPGP4FPR:${fp}" --output "${master}-public-qr-fingerprint.png"
  optipng -silent -preserve -fix -strip all -o3 "${master}-public-qr-fingerprint.png"
qrencode --type svg --inline --svg-path --rle "OPENPGP4FPR:${fp}" | \
  svgcleaner --indent 1 --stdout - > "${master}-public-qr-fingerprint.svg"

id="${mail}"

{
  my_gpg \
    --batch --yes \
    --keyid-format 0xlong \
    --list-public-keys
  my_gpg \
    --batch --yes \
    --keyid-format 0xlong \
    --list-secret-keys
} 2>/dev/null > "${master}-id.txt"

# Export public key
my_gpg \
  --batch --yes --no-tty \
  --keyid-format 0xlong \
  --armor --export "${id}" > "${master}-public.asc"
pgpdump "${master}-public.asc" 2>/dev/null \
      > "${master}-public.asc.dump.txt"
my_gpg --list-packets --verbose --debug 0x02 2>/dev/null \
  < "${master}-public.asc" \
  > "${master}-public.asc.pkt.txt"

my_gpg --batch --dearmor < "${master}-public.asc" | qrencode --type png --output "${master}-public-qr.png"
  optipng -silent -preserve -fix -strip all -o3 "${master}-public-qr.png"
my_gpg --batch --dearmor < "${master}-public.asc" | qrencode --type svg --inline --svg-path --rle | \
  svgcleaner --indent 1 --stdout - > "${master}-public-qr.svg"

# Export private key (encrypted)
echo "${pass}" | my_gpg \
  --batch --yes --no-tty \
  --keyid-format 0xlong \
  --pinentry-mode loopback --passphrase-fd 0 \
  --s2k-cipher-algo aes256 \
  --s2k-digest-algo sha512 \
  --armor --export-secret-key "${id}" > "${master}-private.asc"
pgpdump "${master}-private.asc" 2>/dev/null \
      > "${master}-private.asc.dump.txt"
my_gpg --list-packets --verbose --debug 0x02 2>/dev/null \
  < "${master}-private.asc" \
  > "${master}-private.asc.pkt.txt"

# brew install paperkey
# paperkey --secret-key my-secret-key.gpg --output sec

encr_pass="$(openssl rand 32 | base58)"; readonly encr_pass
privout "${master}-private_gpg.password" \
printf '%s' "${encr_pass}"

# Double-encrypted .asc for distribution
exec 3<<EOF
${encr_pass}
EOF
echo "${pass}" | my_gpg \
  --batch --yes --no-tty \
  --keyid-format 0xlong \
  --pinentry-mode loopback --passphrase-fd 0 \
  --s2k-cipher-algo aes256 \
  --s2k-digest-algo sha512 \
  --export-secret-key "${id}" | \
my_gpg --batch --yes --no-tty \
  --pinentry-mode loopback --passphrase-fd 3 \
  --force-ocb \
  --cipher-algo aes256 --digest-algo sha512 --compress-algo none \
  --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
  --symmetric --no-symkey-cache --output "${master}-private_gpg.asc" --armor

rm -r -f "${dir}"; unset GNUPGHOME
