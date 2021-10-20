#!/bin/sh

export CURL_VER_='7.79.1'
export CURL_HASH=0606f74b1182ab732a17c11613cbbaf7084f2e6cca432642d0e3ad7c224c3689
export BROTLI_VER_='1.0.9'
export BROTLI_HASH=f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46
export LIBGSASL_VER_='1.10.0'
export LIBGSASL_HASH=f1b553384dedbd87478449775546a358d6f5140c15cccc8fb574136fdc77329f
export LIBIDN2_VER_='2.3.2'
export LIBIDN2_HASH=76940cd4e778e8093579a9d195b25fff5e936e9dc6242068528b437a76764f91
export LIBSSH2_VER_='1.10.0'
export LIBSSH2_HASH=2d64e90f3ded394b91d3a2e774ca203a4179f69aebee03003e5a6fa621e41d51
export NGHTTP2_VER_='1.46.0'
export NGHTTP2_HASH=1a68cc4a5732afb735baf50aaac3cb3a6771e49f744bd5db6c49ab5042f12a43
export NGHTTP3_VER_='0.1.90'
export NGHTTP3_HASH=
export NGTCP2_VER_='0.1.90'
export NGTCP2_HASH=
export OPENSSL_VER_='3.0.0'
export OPENSSL_HASH=59eedfcb46c25214c9bd37ed6078297b4df01d012267fe9e9eee31f61bc70536
export ZLIBNG_VER_='2.0.5'
export ZLIBNG_HASH=eca3fe72aea7036c31d00ca120493923c4d5b99fe02e6d3322f7c88dbdcd0085
export ZLIB_VER_='1.2.11'
export ZLIB_HASH=4ff941449631ace0d4d203e3483be9dbc9da454084111f97ea0a2114e19bf066
export ZSTD_VER_='1.5.0'
export ZSTD_HASH=9aa8dfc1ca17f358b28988ca1f6e00ffe1c6f3198853f8d2022799e6f0669180

# Create revision string
# NOTE: Set _REVN to empty after bumping CURL_VER_, and
#       set it to 1 then increment by 1 each time bumping a dependency
#       version or pushing a CI rebuild for the main branch.
export _REVN=2

export _REV="${_REVN}"; [ -z "${_REV}" ] || _REV="_${_REV}"
