#!/bin/bash

set -o errexit

REPO_DIR=$(readlink -f $(dirname $0)/../..)
BINDINGS_PATH=${REPO_DIR}/mongocrypt-sys/src/bindings.rs
LIBMONGOCRYPT_DIR=${LIBMONGOCRYPT_DIR:-"${REPO_DIR}/../libmongocrypt"}
if [ ! -f $LIBMONGOCRYPT_DIR/src/mongocrypt.h ]; then
    echo 'LIBMONGOCRYPT_DIR must point to the base directory of the libmongocrypt repo.'
    exit 1
fi
if [ -z "$LIBMONGOCRYPT_TAG" ]; then
    echo 'LIBMONGOCRYPT_TAG must be set to the release tag to use (e.g. "1.5.0-rc0").'
    exit 1
fi

cd $LIBMONGOCRYPT_DIR
git checkout $LIBMONGOCRYPT_TAG
mkdir -p cmake-build
cmake -DENABLE_SHARED_BSON=ON . -Bcmake-build
bindgen src/mongocrypt.h \
    -o $BINDINGS_PATH \
    --allowlist-function 'mongocrypt_.*' \
    -- -I cmake-build/src
