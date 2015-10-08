#!/bin/sh

# Create a fixed seed based on the timestamp of the OpenSSL source package

cd "$(dirname "$0")" || exit

ts=$(stat -c %W openssl/CHANGES)

stat -c %w openssl/CHANGES
stat -c %y openssl/CHANGES
stat -c %W openssl/CHANGES
stat -c %Y openssl/CHANGES

sed -e "s/-frandom-seed=__RANDOM_SEED__/-frandom-seed=${ts}/g" -i openssl.diff
sed -e "s/-frandom-seed=__RANDOM_SEED__/-frandom-seed=${ts}/g" -i mk-openssl.bat

unix2dos mk-openssl.bat
