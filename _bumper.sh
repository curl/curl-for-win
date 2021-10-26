#!/bin/sh

# Copyright 2021-present Viktor Szakats. See LICENSE.md

if ! command -v hxclean >/dev/null 2>&1; then
  case "$(uname)" in
    Linux*)
      apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
      apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
        curl git gpg zip zstd jq html-xml-utils;;
    Darwin*)
      brew install \
        curl git gpg zip zstd jq html-xml-utils;;
  esac
fi

. ./_versions.sh

./_dl.sh bump
