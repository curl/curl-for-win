#!/bin/sh

# Copyright 2017-2018 Viktor Szakats <https://vszakats.net/>
# See LICENSE.md

_BRANCH="${APPVEYOR_REPO_BRANCH}${TRAVIS_BRANCH}${CI_COMMIT_REF_NAME}${GIT_BRANCH}"

cat /etc/*-release

export _CCSUFFIX='-6.0'
[ "${CC}" = 'mingw-clang' ] && _optpkg="clang${_CCSUFFIX}"
[ "${_BRANCH#*dev*}" != "${_BRANCH}" ] && _optpkg="${_optpkg} autoconf automake libtool"

dpkg --add-architecture i386
apt-get -qq update
# shellcheck disable=SC2086
apt-get -qq install \
  curl git make python3-pip \
  gcc-mingw-w64 ${_optpkg} cmake \
  zip time jq dos2unix osslsigncode wine64 wine32

./_build.sh
