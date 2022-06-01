#!/bin/bash

set -o errexit
set -o nounset
set -x

REPO_DIR=$(readlink -f $(dirname $0)/../..)
BINDINGS_PATH=${REPO_DIR}/mongocrypt-sys/src/bindings.rs
LIBMONGOCRYPT_DIR=${LIBMONGOCRYPT_DIR:-"${REPO_DIR}/../libmongocrypt"}
if [ ! -f $LIBMONGOCRYPT_DIR/src/mongocrypt.h.in ]; then
    echo 'LIBMONGOCRYPT_DIR must point to the base directory of the libmongocrypt repo'
    exit 1
fi
LIBMONGOCRYPT_TAG=${LIBMONGOCRYPT_TAG:-'1.5.0-rc0'}

cd $LIBMONGOCRYPT_DIR
git checkout $LIBMONGOCRYPT_TAG
mkdir -p cmake-build
cmake -DENABLE_SHARED_BSON=ON . -Bcmake-build
bindgen cmake-build/src/mongocrypt.h \
    -o $BINDINGS_PATH \
    --allowlist-function 'mongocrypt_.*' \
    -- -I src
