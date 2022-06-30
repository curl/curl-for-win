#!/bin/sh

# Copyright 2021-present Viktor Szakats. See LICENSE.md

if ! command -v hxclean >/dev/null 2>&1; then
  case "$(uname)" in
    Linux*)
      apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
      apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
        curl git gpg zip jq html-xml-utils;;
    Darwin*)
      brew install \
        curl git gpg zip jq html-xml-utils;;
  esac
fi

. ./_versions.sh

./_dl.sh bump

# Find out the latest docker image release:

name='debian'

# https://docs.docker.com/registry/spec/api/
token="$(curl --disable --user-agent '' --silent --fail --show-error \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/${name}:pull" \
  | jq --raw-output '.token')"

tag="$(curl --disable --user-agent '' --silent --fail --show-error \
    --header 'Accept: application/json' \
    --header @/dev/stdin \
    "https://registry-1.docker.io/v2/library/${name}/tags/list" <<EOF \
  | jq --raw-output '.tags[]' | grep -E '^testing-[0-9]{8}-slim$' | sort | tail -1
Authorization: Bearer ${token}
EOF
)"

echo; echo "  DOCKER_IMAGE: ${name}:${tag}"
