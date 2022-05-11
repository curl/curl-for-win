#!/bin/sh

export CURL_VER_='7.83.1'
export CURL_HASH=2cb9c2356e7263a1272fd1435ef7cdebf2cd21400ec287b068396deb705c22c4
export BROTLI_VER_='1.0.9'
export BROTLI_HASH=f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46
export LIBGSASL_VER_='1.10.0'
export LIBGSASL_HASH=f1b553384dedbd87478449775546a358d6f5140c15cccc8fb574136fdc77329f
export LIBIDN2_VER_='2.3.2'
export LIBIDN2_HASH=76940cd4e778e8093579a9d195b25fff5e936e9dc6242068528b437a76764f91
export LIBSSH2_VER_='1.10.0'
export LIBSSH2_HASH=2d64e90f3ded394b91d3a2e774ca203a4179f69aebee03003e5a6fa621e41d51
export NGHTTP2_VER_='1.47.0'
export NGHTTP2_HASH=68271951324554c34501b85190f22f2221056db69f493afc3bbac8e7be21e7cc
export NGHTTP3_VER_='0.1.90'
export NGHTTP3_HASH=
export NGTCP2_VER_='0.1.90'
export NGTCP2_HASH=
export OPENSSL_VER_='3.0.3'
export OPENSSL_HASH=ee0078adcef1de5f003c62c80cc96527721609c6f3bb42b7795df31f8b558c0b
export OSSLSIGNCODE_VER_='2.3.0'
export OSSLSIGNCODE_HASH=b73a7f5a68473ca467f98f93ad098142ac6ca66a32436a7d89bb833628bd2b4e
export ZLIB_VER_='1.2.12'
export ZLIB_HASH=7db46b8d7726232a621befaab4a1c870f00a90805511c0e0090441dac57def18
export PEFILE_VER_='2021.9.3'

# Create revision string
# NOTE: Set _REV to empty after bumping CURL_VER_, and
#       set it to 1 then increment by 1 each time bumping a dependency
#       version or pushing a CI rebuild for the main branch.
export _REV=''
