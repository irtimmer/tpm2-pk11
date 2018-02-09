#!/usr/bin/env bash

# fail if any failure
set -e

# only test against master tss for now
if [ ${TSS_BRANCH} == "master" ]; then
    pushd ${TRAVIS_BUILD_DIR}/build
    bats ${TRAVIS_BUILD_DIR}/test/bat/bats.bat
    popd
fi
