#!/bin/bash
# Script to build and upload tarball for arm64
# Requires cargo-dist and Github's cli "gh"
#

set -e
set -x

if [ "$#" -ne 1 ]; then
    echo "This script does takes one argument: tag (should be a git tag)"
    exit 1
fi


TAG=$1
GIT_REPO_ROOT=$(git rev-parse --show-toplevel)
PRODUCT=mrlog

echo building tarball
cargo dist build

echo uploading release

gh release upload $TAG $GIT_REPO_ROOT/target/distrib/$PRODUCT-aarch64-unknown-linux-gnu.tar.xz

echo done