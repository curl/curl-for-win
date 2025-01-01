#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

export DOCKER_IMAGE='debian:testing-20241223-slim'
export DOCKER_CONTENT_TRUST='1'

export CURL_VER_='8.11.1'
export CURL_HASH=c7ca7db48b0909743eaef34250da02c19bc61d4f1dcedd6603f109409536ab56
# Create revision string
# NOTE: Set _REV to 1 after bumping CURL_VER_, then increment for each
#       CI rebuild via `main` branch push (e.g. after bumping a dependency).
export _REV="${CW_REVISION:-2}"

export TRURL_VER_='0.16'
export TRURL_HASH=2c26e3016f591f06234838bbe1dd4b165dce2c871c82ca6a32222d19696588d6

export CACERT_VER_='2024-12-31'
export CACERT_HASH=a3f328c21e39ddd1f2be1cea43ac0dec819eaa20a90425d7da901a11531b3aa5
export BROTLI_VER_='1.1.0'
export BROTLI_HASH=e720a6ca29428b803f4ad165371771f5398faba397edf6778837a18599ea13ff
export CARES_VER_='1.34.4'
export CARES_HASH=fa38dbed659ee4cc5a32df5e27deda575fa6852c79a72ba1af85de35a6ae222f
export LIBPSL_VER_='0.21.5'
export LIBPSL_HASH=1dcc9ceae8b128f3c0b3f654decd0e1e891afc6ff81098f227ef260449dae208
export LIBSSH_VER_='0.11.1'
export LIBSSH_HASH=14b7dcc72e91e08151c58b981a7b570ab2663f630e7d2837645d5a9c612c1b79
export LIBSSH2_VER_='1.11.1'
export LIBSSH2_HASH=9954cb54c4f548198a7cbebad248bdc87dd64bd26185708a294b2b50771e3769
export LIBSSH2_CPPFLAGS='-DLIBSSH2_NO_BLOWFISH -DLIBSSH2_NO_RC4 -DLIBSSH2_NO_HMAC_RIPEMD -DLIBSSH2_NO_CAST -DLIBSSH2_NO_3DES -DLIBSSH2_NO_MD5'
export NGHTTP2_VER_='1.64.0'
export NGHTTP2_HASH=88bb94c9e4fd1c499967f83dece36a78122af7d5fb40da2019c56b9ccc6eb9dd
export NGHTTP3_VER_='1.7.0'
export NGHTTP3_HASH=b4eb6bceb99293d9a9df2031c1aad166af3d57b3e33655aca0699397b6f0d751
export NGTCP2_VER_='1.10.0'
export NGTCP2_HASH=4f8dc1d61957205d01c3d6aa6f1c96c7b2bac1feea71fdaf972d86db5f6465df
export QUICTLS_VER_='3.3.0'
export QUICTLS_HASH=392b6784ca12b9f068582212a9498366ffd3dd1bafe79507046bdd1a6a138cc9
export OPENSSL_VER_='3.4.0'
export OPENSSL_HASH=e15dda82fe2fe8139dc2ac21a36d4ca01d5313c75f99f46c4e8a27709b7294bf
export BORINGSSL_VER_='0.20241209.0'
export BORINGSSL_HASH=243a4fbfa4e749fecc73e58f62f25ab2e41edcc4f34fa23b4b6afe0e0babb2ad
export AWSLC_VER_='1.41.1'
export AWSLC_HASH=c81376005466339564c3ca5ad83c52ca350f79391414999d052b5629d008a4d6
export LIBRESSL_VER_='4.0.0'
export LIBRESSL_HASH=4d841955f0acc3dfc71d0e3dd35f283af461222350e26843fea9731c0246a1e4
export OSSLSIGNCODE_VER_='2.9.0'
export OSSLSIGNCODE_HASH=3fe5488e442ad99f91410efeb7b029275366b5df9aa02371dcc89a8f8569ff55
export ZLIBNG_VER_='2.2.3'
export ZLIBNG_HASH=f2fb245c35082fe9ea7a22b332730f63cf1d42f04d84fe48294207d033cba4dd
export ZLIB_VER_='1.3.1'
export ZLIB_HASH=38ef96b8dfe510d42707d9c781877914792541133e1870841463bfa73f883e32
export ZSTD_VER_='1.5.6'
export ZSTD_HASH=8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1
export LLVM_MINGW_LINUX_AARCH64_VER_='20241217'
export LLVM_MINGW_LINUX_AARCH64_HASH=ebd39c9f3a887d404d3fb86a12d4de51b72a3de93d1bf5487e117bf3748d477d
export LLVM_MINGW_LINUX_X86_64_VER_='20241217'
export LLVM_MINGW_LINUX_X86_64_HASH=cfe4aac3d245a77d8cd0c41bdcd7971b1002c771d3bba2ac39702733b0fb0c12
export LLVM_MINGW_MAC_VER_='20241217'
export LLVM_MINGW_MAC_HASH=c70c131dcfd415ab7c227404c248905528f5fbe1cca6d868c55d690ceae89dc4
export LLVM_MINGW_WIN_VER_='20241217'
export LLVM_MINGW_WIN_HASH=f4f3ad8616c4183ce7b0d72df634400945b41ea9816145fc2430df6003455db7
