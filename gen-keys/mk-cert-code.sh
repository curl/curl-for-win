#!/bin/sh

# To the extent possible under law, Viktor Szakats
# has waived all copyright and related or neighboring rights to this script.
# CC0 - https://creativecommons.org/publicdomain/zero/1.0/
# SPDX-License-Identifier: CC0-1.0

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# This script creates a self-signed root certificate, along with a code
# signing certificate in various formats, trying to use the best available
# crypto/practice all along. Then, it creates a test executable and code sign
# it using both osslsigncode and signtool.exe (on Windows only) and verify
# those signature using osslsigncode and sigcheck.exe (on Windows only).

# Requires:
#   openssl 1.1.x+, gpg, osslsigncode 2.1.0+, GNU tail, base58
# Debian:
#   apt install osslsigncode base58
# Mac:
#   brew install openssl gnupg osslsigncode coreutils diffutils
# Windows:
#   pacman --sync openssl gnupg mingw-w64-{i686,x86_64}-osslsigncode
#   sigcheck64.exe:
#     curl --user-agent '' --remote-name --remote-time --xattr https://live.sysinternals.com/tools/sigcheck64.exe
#   signtool.exe:
#     part of Windows SDK

# - .pem is a format, "Privacy Enhanced Mail", text, base64-encoded binary
#           (with various twists, if encrypted)
# - .der is a format, Distinguished Encoding Rules for ASN.1, binary
# - .crt/.cer denote a certificate or multiple certificates
# - .csr is certificate signing request, DER format.
# - .srl is serial number (for certificate generation)
# - .pfx is Microsoft name for .p12
#           = PKCS #12 = encrypted certificate(s) + private keys, DER format.
#           Strictly PKCS #12-compliant systems (like MS/Apple tools) only
#           understand weakly encrypted, standard .p12 files. OpenSSL-based
#           tools (like osslsigncode) accept modern crypto algos as well.
#           Fun read: https://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html
# - .pvk is Microsoft proprietary Private Key format, encrypted (weak crypto)
# - .spc is Microsoft name for .p7b (PKCS #7) = Software Publisher Certificate
#           (or Certificate Bundle), internally it is DER format and contains
#           certificates.
#
# - private-key ASN.1 data structure in PEM or DER format
# - public-key  ASN.1 data structure in PEM or DER format, but it may also
#               exist in one-liner OpenSSH key format RFC 4251.

case "$(uname)" in
  *Darwin*)
    alias openssl=/usr/local/opt/openssl/bin/openssl
    readonly os='mac';;
  *_NT*)
    # To find osslsigncode
    PATH="/mingw64/bin:${PATH}"
    readonly os='win';;
  Linux*)
    readonly os='linux';;
esac

# Redirect stdout securely to non-world-readable files
privout() {
  o="$1"; rm -f "$o"; install -m 600 /dev/null "$o"; shift
  (
    "$@"
  ) >> "$o"
}

readonly base="$1"
readonly revi="$2"

if [ -n "${4:-}" ]; then
  readonly compname="$4"
else
  readonly compname="${base}"
fi

what='Code'

[ -n "${base}" ] || exit 1

echo "OpenSSL      $(openssl version 2>/dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9a-z]+')"
echo "osslsigncode $(osslsigncode -v 2>/dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9]+')"

# C  = Country
# L  = Locality
# ST = State
# O  = Organization
# CN = Common Name

readonly prfx="${base}_${revi}-"
readonly root="${prfx}ca"

echo '! Creating self-signed Root Certificate...'

# https://pki-tutorial.readthedocs.io/en/latest/simple/root-ca.conf.html
# https://en.wikipedia.org/wiki/X.509

if [ "${3:-}" = 'rsa' ]; then
  cryptopt='-algorithm RSA -pkeyopt rsa_keygen_bits:4096'
else
  # TODO:
  #   https://github.com/openssl/openssl/pull/18809
  #   https://github.com/openssl/openssl/pull/9223
  #     -pkeyopt ecdsa_nonce_type:deterministic
  #     or? -sigopt ecdsa_nonce_type:deterministic
  cryptopt='-algorithm EC  -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve'
fi

# reuse password if found on disk
if [ -r "${root}.password" ]; then
  root_pass="$(cat "${root}.password")"; readonly root_pass
else
  # "$(pwgen --secure 40 1)"
  root_pass="$(openssl rand 32 | base58)"; readonly root_pass
  privout "${root}.password" \
  printf '%s' "${root_pass}"
fi

# PKCS #8 private key, encrypted, PEM format.
# shellcheck disable=SC2086
echo "${root_pass}" | openssl genpkey ${cryptopt} -aes-256-cbc -pass fd:0 -out "${root}-private.pem" 2>/dev/null
privout "${root}-private.pem.asn1.txt" \
openssl asn1parse -i -in "${root}-private.pem"
# echo "${root_pass}" | openssl pkey -in "${root}-private.pem" -passin fd:0 -text -noout -out "${root}-private.pem.txt"

# Alternatives for passing a second secret to openssl:
#   exec 3<>"${root}.password" (POSIX, needs password file)
#   openssl ... -passin "file:${root}.password" (needs password file)
#   openssl ... 3<<<"${root_pass}" (non-POSIX)
#   exec 3<<<"${root_pass}" (non-POSIX)

# -cert.pem is certificate (public key + subject + signature)
exec 3<<EOF
${root_pass}
EOF
openssl req -batch -verbose -new -sha512 -x509 -days 1826 -passin fd:3 -key "${root}-private.pem" -out "${root}-cert.pem" -config - << EOF
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
x509_extensions = v3_ca

[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign

[dn]
CN = ${compname} Root CA ${revi}
EOF
openssl x509 -in "${root}-cert.pem" -text -noout -nameopt utf8 -sha256 -fingerprint > "${root}-cert.pem.x509.txt"
openssl asn1parse -i -in "${root}-cert.pem" > "${root}-cert.pem.asn1.txt"

# subordinates (do not set exactly the same 'subject' data as above)

# subordinate #1: code signing

readonly code="${prfx}code"

cat << EOF > "${code}-csr.config"
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
req_extensions = v3_req

[v3_req]
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
# msCodeInd = Microsoft Individual Code Signing
# msCodeCom = Microsoft Commercial Code Signing
extendedKeyUsage = critical, codeSigning, msCodeInd

[dn]
CN = ${compname} ${what} Signing Authority
EOF

echo "! Creating ${what} Signing Certificate..."

# reuse password if found on disk
if [ -r "${code}.password" ]; then
  code_pass="$(cat "${code}.password")"; readonly code_pass
else
  # "$(pwgen --secure 40 1)"
  code_pass="$(openssl rand 32 | base58)"; readonly code_pass
  privout "${code}.password" \
  printf '%s' "${code_pass}"
fi

# PKCS #8 private key, encrypted, PEM format.
# shellcheck disable=SC2086
echo "${code_pass}" | openssl genpkey ${cryptopt} -aes-256-cbc -pass fd:0 -out "${code}-private.pem" 2>/dev/null
privout "${code}-private.pem.asn1.txt" \
openssl asn1parse -i -in "${code}-private.pem"
# Do not dump a decrypted private key
# echo "${code_pass}" | openssl pkey -in "${code}-private.pem" -passin fd:0 -text -noout -out "${code}-private.pem.txt"

echo "${code_pass}" | openssl pkey -passin fd:0 -in "${code}-private.pem" -pubout > "${code}-public.pem"
# Play some with the public key
openssl pkey -pubin -in "${code}-public.pem" -text -noout > "${code}-public.pem.txt"
openssl asn1parse -i -in "${code}-public.pem" > "${code}-public.pem.asn1.txt"

# -csr.pem is certificate signing request
echo "${code_pass}" | openssl req -batch -verbose -new -sha512 -passin fd:0 -key "${code}-private.pem" -out "${code}-csr.pem" -config "${code}-csr.config"
openssl req -batch -verbose -in "${code}-csr.pem" -text -noout -nameopt utf8 > "${code}-csr.pem.txt"
openssl asn1parse -i -in "${code}-csr.pem" > "${code}-csr.pem.asn1.txt"

# -cert.pem is certificate (public key + subject + signature)
echo "${root_pass}" | openssl x509 -req -sha512 -days 1095 \
  -extfile "${code}-csr.config" -extensions v3_req \
  -in "${code}-csr.pem" -passin fd:0 \
  -CA "${root}-cert.pem" -CAkey "${root}-private.pem" -CAcreateserial -out "${code}-cert.pem"
openssl x509 -in "${code}-cert.pem" -text -noout -nameopt utf8 -sha256 -fingerprint > "${code}-cert.pem.x509.txt"
# Extract SHA1 fingerprint for Windows signtool.exe
openssl x509 -in "${code}-cert.pem"       -noout -nameopt utf8 -sha1   -fingerprint | grep -a -o -E '[A-Z0-9:]{59}' | tr -d ':' > "${code}-cert-sha1.txt"
openssl x509 -in "${code}-cert.pem"       -noout -nameopt utf8 -sha256 -fingerprint | grep -a -o -E '[A-Z0-9:]{95}' | tr -d ':' > "${code}-cert-sha256.txt"
openssl asn1parse -i -in "${code}-cert.pem" > "${code}-cert.pem.asn1.txt"

# You can include/exclude the root certificate by adding/removing option:
#   `-chain -CAfile "${root}-cert.pem"`
# PKCS #12 .p12 is private key and certificate(-chain), encrypted
exec 3<<EOF
${code_pass}
EOF
echo "${code_pass}" | openssl pkcs12 -export \
  -keypbe aes-256-cbc -certpbe aes-256-cbc -macalg sha512 \
  -passout fd:3 \
  -passin fd:0 -inkey "${code}-private.pem" \
  -in "${code}-cert.pem" \
  -chain -CAfile "${root}-cert.pem" \
  -out "${code}.p12"
# `-nokeys` option avoids dumping unencrypted private key
# (keeping the output private anyway)
echo "${code_pass}" | openssl pkcs12 -passin fd:0 -in "${code}.p12" -info -nodes -nokeys -out "${code}.p12.txt"
privout "${code}.p12.asn1.txt" \
openssl asn1parse -i -inform DER -in "${code}.p12"

# Windows cannot decrypt it if any secure option is used, so create one with
# weak encryption:
exec 3<<EOF
${code_pass}
EOF
echo "${code_pass}" | openssl pkcs12 -export \
  -legacy -iter 3000000 \
  -passout fd:3 \
  -passin fd:0 -inkey "${code}-private.pem" \
  -in "${code}-cert.pem" \
  -chain -CAfile "${root}-cert.pem" \
  -out "${code}-weak.p12"
# `-nokeys` option avoids dumping unencrypted private key
# (keeping the output private anyway)
echo "${code_pass}" | openssl pkcs12 -passin fd:0 -in "${code}-weak.p12" -info -nodes -nokeys -out "${code}-weak.p12.txt" -legacy
privout "${code}-weak.p12.asn1.txt" \
openssl asn1parse -i -inform DER -in "${code}-weak.p12"

# reuse password if found on disk
if [ -r "${code}.p12.gpg.password" ]; then
  encr_pass="$(cat "${code}.p12.gpg.password")"; readonly encr_pass
else
  # "$(pwgen --secure 40 1)"
  # Make sure password does not start with '/'. Some tools can mistake it for
  # an option.
  encr_pass="$(openssl rand 32 | base58)"; readonly encr_pass
  privout "${code}.p12.gpg.password" \
  printf '%s' "${encr_pass}"
fi

# Encrypted .p12 for distribution (ASCII, binary)
echo "${encr_pass}" | gpg --batch --verbose --yes --no-tty \
  --pinentry-mode loopback --passphrase-fd 0 \
  --force-ocb \
  --cipher-algo aes256 --digest-algo sha512 --compress-algo none \
  --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
  --symmetric --no-symkey-cache --output "${code}.p12.asc" --armor \
  --set-filename '' "${code}.p12"

echo "${encr_pass}" | gpg --batch --verbose --yes --no-tty \
  --pinentry-mode loopback --passphrase-fd 0 \
  --force-ocb \
  --cipher-algo aes256 --digest-algo sha512 --compress-algo none \
  --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
  --symmetric --no-symkey-cache --output "${code}.p12.gpg" \
  --set-filename '' "${code}.p12"

echo '! Test signing an executable...'

# Code signing for Windows

readonly test="${5:-test.exe}"

if [ "${test}" = 'test.exe' ]; then
  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo 'int main(void) { return 0; }' | x86_64-w64-mingw32-gcc -x c - -s -o "${test}"
  else
    # Re-create minimal (runnable) PE executable.
    # Dump created using:
    #   curl --user-agent 'Mozilla/5.0' \
    #     -L https://web.archive.org/web/20090609113616/phreedom.org/research/tinype/tiny.c.468/tiny.exe \
    #   | openssl base64 -e > tiny.exe.b64
    #   # SHA2-256: bd82090d9c6e23c1e2708550f4c21bbafd719dcc7cfc28f405ad3bc2783c6a12
    #   # SHA2-512: fd6904a7b7e4fc015bf8d50435b73944494c7b99ec9a19d6fdf958fbfe6c3d7a7f54ff9e73eac9d07c22d5fc0cb8d5ab55f2c94ebf90270e842128999d836c66
    cat << EOF | openssl base64 -d > "${test}"
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAsAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v
dCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAD5LXLZvUwcir1MHIq9TByK
mopxirxMHIqaimSKvEwcilJpY2i9TByKAAAAAAAAAABQRQAATAEBAF2+RUUAAAAA
AAAAAOAAAwELAQgABAAAAAAAAAAAAAAA0AEAANABAADUAQAAAABAAAEAAAABAAAA
BAAAAAAAAAAEAAAAAAAAANQBAADQAQAAAAAAAAIAAAQAABAAABAAAAAAEAAAEAAA
AAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC50ZXh0AAAA
BAAAANABAAAEAAAA0AEAAAAAAAAAAAAAAAAAACAAAGBqKljD
EOF
    openssl dgst -sha256 "${test}"
  fi
fi

if [ -f "${test}" ]; then

  find . -name "${test%.exe}-signed*.exe" -delete

  readonly ts="${MY_TIME_SERVER:-https://freetsa.org/tsr}"

  # using osslsigncode

  # - osslsigncode is not deterministic and it also includes all certificates
  #   from the .p12 file.
  #   It always uses `Microsoft Individual Code Signing`, regardless of
  #   the `extendedKeyUsage` value in the signing certificate. Can switch
  #   to Commercial by passing `-comm` option.
  # - signtool appears to be deterministic and excludes the root certificate.
  #   Root (and intermediate) cert(s) can be added via -ac option.
  #   It honors the Commercial/Individual info in `extendedKeyUsage`.
  #   if both are specified, it is Commercial,
  #   if none, it is Individual.
  #   Ref: https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537364(v=vs.85)#signcode

  temp='./_code.p12'
  rm -f "${temp}"
  echo "${encr_pass}" | gpg --batch --no-tty \
    --pinentry-mode loopback --passphrase-fd 0 \
    --output "${temp}" --decrypt "${code}.p12.asc"

  case "$(uname)" in
    Darwin*|*BSD) unixts="$(TZ=UTC stat -f '%m'       "${test}")";;
    *)            unixts="$(TZ=UTC stat --format '%Y' "${test}")";;
  esac

  echo "${code_pass}" | osslsigncode sign -h sha512 \
    -in "${test}" -out "${test%.exe}-signed-ossl-ts-1.exe" \
    -ts "${ts}" \
    -pkcs12 "${temp}" -readpass /dev/stdin

  echo "${code_pass}" | osslsigncode sign -h sha512 \
    -in "${test}" -out "${test%.exe}-signed-ossl-1.exe" \
    -time "${unixts}" \
    -pkcs12 "${temp}" -readpass /dev/stdin
  sleep 3
  echo "${code_pass}" | osslsigncode sign -h sha512 \
    -in "${test}" -out "${test%.exe}-signed-ossl-2.exe"  \
    -time "${unixts}" \
    -pkcs12 "${temp}" -readpass /dev/stdin

  rm -f "${temp}"

  # osslsigncode is non-deterministic, even if not specifying a timestamp
  # server, because openssl PKCS #7 code unconditionally includes the local
  # timestamp inside a `signingTime` PKCS #7 record.
  if cmp --quiet -- \
       "${test%.exe}-signed-ossl-1.exe" \
       "${test%.exe}-signed-ossl-2.exe"; then
    echo '! Info: osslsigncode code signing: deterministic'
  else
    echo '! Info: osslsigncode code signing: non-deterministic'
  fi

  # using signtool.exe

  if [ "${os}" = 'win' ]; then

    # Root CA may need to be installed as a "Trust Root Certificate".
    # It has to be confirmed on a GUI dialog:
    #   certutil.exe -addStore -user -f 'Root' "${root}-cert.pem"

    code_hash="$(cat "${code}-cert-sha1.txt")"

    cp -p "${test}" "${test%.exe}-signed-ms-ts.exe"
    signtool.exe sign -fd sha512 \
      -sha1 "${code_hash}" \
      -td sha512 -tr "${ts}" \
      "${test%.exe}-signed-ms-ts.exe"

    cp -p "${test}" "${test%.exe}-signed-ms-1.exe"
    signtool.exe sign -fd sha512 \
      -sha1 "${code_hash}" \
      "${test%.exe}-signed-ms-1.exe"
    sleep 3
    cp -p "${test}" "${test%.exe}-signed-ms-2.exe"
    signtool.exe sign -fd sha512 \
      -sha1 "${code_hash}" \
      "${test%.exe}-signed-ms-2.exe"

    # Remove root CA:
    #   certutil.exe -delStore -user 'Root' "$(openssl x509 -noout -subject -in "${root}-cert.pem" | sed -n '/^subject/s/^.*CN=//p')"

    # signtool.exe is deterministic, unless we specify a timestamp server
    if cmp --quiet -- \
         "${test%.exe}-signed-ms-1.exe" \
         "${test%.exe}-signed-ms-2.exe"; then
      echo '! Info: signtool.exe code signing: deterministic'
    else
      echo '! Info: signtool.exe code signing: non-deterministic'
    fi
  fi

  if osslsigncode verify -CAfile "${root}-cert.pem" "${test}" 2>/dev/null | grep -q 'Signature verification: ok'; then
    echo "! Fail: unsigned exe passes: ${test}"
  else
    echo "! OK: unsigned exe fails: ${test}"
  fi

  for file in "${test%.exe}"-*.exe; do

    # Dump PKCS #7 signature record as PEM and as human-readable text
    osslsigncode extract-signature \
      -in "${file}" -pem -out "${file}.pkcs7" >/dev/null
    openssl asn1parse -i -inform PEM -in "${file}.pkcs7" > "${file}.pkcs7.asn1.txt" || true

    # Verify signature with osslsigncode
    if osslsigncode verify -CAfile "${root}-cert.pem" "${file}" 2>/dev/null | grep -q 'Signature verification: ok'; then
      echo "! OK: signed exe passes 'osslsigncode verify': ${file}"
    else
      echo "! Fail: signed exe fails 'osslsigncode verify': ${file}"
    fi

    unset wine
    [ "${os}" = 'win' ] || wine=wine

    if [ "${os}" = 'win' ]; then
      # TODO: verify using `signtool.exe verify`

      # Verify signature with sigcheck
      if "${wine}" sigcheck64.exe -nobanner -accepteula "${file}"; then
        # If we have not specified a timestamp server when code signing,
        # sigcheck reports the _current time_ as "Signing date".
        echo "! OK: signed exe passes 'sigcheck64.exe': ${file}"
      else
        echo "! Fail: signed exe fails 'sigcheck64.exe': ${file}"
      fi
    fi
  done
else
  echo "! Error: '${test}' not found."
fi
