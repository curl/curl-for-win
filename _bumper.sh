#!/bin/sh

# Copyright 2021-present Viktor Szakats. See LICENSE.md

case "$(uname)" in
  Linux*)
    apt-get --quiet 2 --option Dpkg::Use-Pty=0 update
    apt-get --quiet 2 --option Dpkg::Use-Pty=0 install \
      curl git gpg zip zstd jq html-xml-utils;;
esac

./_dl.sh bump
