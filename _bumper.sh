#!/bin/sh

# Copyright (C) Viktor Szakats. See LICENSE.md
# SPDX-License-Identifier: MIT

# shellcheck disable=SC3040,SC2039
set -o errexit -o nounset; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

cd "$(dirname "$0")"

if ! command -v hxclean >/dev/null 2>&1; then
  case "$(uname)" in
    Linux*)
      apt-get --option Dpkg::Use-Pty=0 --yes update
      apt-get --option Dpkg::Use-Pty=0 --yes install --no-install-suggests --no-install-recommends \
        curl git gpg zip jq html-xml-utils;;
    Darwin*)
      brew install \
        curl git gpg jq html-xml-utils;;
  esac
fi

export _CONFIG="${1:-}"

. ./_versions.sh

./_dl.sh bump

# Find out the latest container image releases:

echo

name='debian'

# Architecture-agnostic image hash:
# $ regctl image digest debian:trixie-slim

dockerhub_token() {
  # https://docs.docker.com/reference/api/registry/latest/
  curl --disable --user-agent '' --silent --fail --show-error \
      "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/$1:pull" \
    | jq --raw-output '.token'
}

dockerhub_latest_tag() {
  token="$1"
  name="$2"
  release="$3"
  # collect all tags. Each request returns 1000 tags max.
  url="https://registry-1.docker.io/v2/library/${name}/tags/list"
  while true; do
    curl --disable --user-agent '' --silent --fail --show-error \
      --header 'Accept: application/json' \
      --header @/dev/stdin \
      "${url}" <<EOF \
      | jq --raw-output '.tags[]'
Authorization: Bearer ${token}
EOF

    # Extract next page from header:
    # "link": [
    #   "</v2/library/debian/tags/list?last=oldoldstable-20201012-slim&n=1000>; rel=\"next\""
    # ]
    # -> /v2/library/debian/tags/list?last=oldoldstable-20201012-slim&n=1000
    next="$(curl --disable --user-agent '' --silent --fail --show-error \
      --header 'Accept: application/json' \
      --header @/dev/stdin \
      "${url}" --write-out '%{header_json}' --output /dev/null <<EOF \
        | jq --raw-output '.link[0]' | cut '-d;' -f 1 | tr -d '<>'
Authorization: Bearer ${token}
EOF
)"
    [ "${next}" = 'null' ] && break
    url="$(printf 'https://registry-1.docker.io%s' "${next}")"
  done | grep -E "^${release}-[0-9]{8}-slim\$" | sort | tail -n -1
}

token="$(dockerhub_token "${name}")"

for release in 'testing' 'trixie'; do
  tag="$(dockerhub_latest_tag "${token}" "${name}" "${release}")"

  # Architecture-agnostic image hash:
  digest="$(curl --disable --user-agent '' --silent --fail --show-error --head --write-out '%header{docker-content-digest}' --output /dev/null \
      --header 'Accept: application/json' \
      --header @/dev/stdin \
      "https://registry-1.docker.io/v2/library/${name}/manifests/${tag}" <<EOF
Authorization: Bearer ${token}
EOF
)"

  if [ "${release}" = 'testing' ]; then
    oci='OCI_IMAGE_DEBIAN_TESTING'
  else
    oci='OCI_IMAGE_DEBIAN_STABLE'
  fi
  echo "export ${oci}='${name}:${tag}@${digest}'"
done

name='alpine'
tag='latest'
token="$(dockerhub_token "${name}")"
# Architecture-agnostic image hash:
digest="$(curl --disable --user-agent '' --silent --fail --show-error --head --write-out '%header{docker-content-digest}' --output /dev/null \
    --header 'Accept: application/json' \
    --header @/dev/stdin \
    "https://registry-1.docker.io/v2/library/${name}/manifests/${tag}" <<EOF
Authorization: Bearer ${token}
EOF
)"
echo "export OCI_IMAGE_ALPINE_LATEST='${name}:${tag}@${digest}'"

# Find out the latest AppVeyor CI Ubuntu worker image

if false; then
  image="$(curl --disable --user-agent '' --silent --fail --show-error \
    'https://www.appveyor.com/docs/build-environment/' \
    | grep -a -o -E 'Ubuntu[0-9]{4}' | sort | tail -n -1)"

  echo; echo "image: ${image}"
fi

# Find out the latest llvm version offered by Debian testing

llvm_latest="$(curl --disable --user-agent 'curl' --silent --fail --show-error \
  'https://packages.debian.org/search?keywords=llvm&searchon=names&suite=testing&section=all' \
  | hxclean | hxselect -i -c -s '\n' 'h3' \
  | grep -a -o -E 'llvm-[0-9]+' | sort -u | tail -n -1)"

echo; echo "export CW_CCSUFFIX='$(echo "${llvm_latest}" | cut -c 5-)'  # ${llvm_latest} (in debian:testing)"
