#!/bin/bash

set -o xtrace
set -o errexit

## Rust

export RUSTUP_HOME="${PROJECT_DIRECTORY}/.rustup"
export CARGO_HOME="${PROJECT_DIRECTORY}/.cargo"

# Make sure to use msvc toolchain rather than gnu, which is the default for cygwin
if [ "Windows_NT" == "$OS" ]; then
    export DEFAULT_HOST_OPTIONS='--default-host x86_64-pc-windows-msvc'
    # rustup/cargo need the native Windows paths; $PROJECT_DIRECTORY is a cygwin path
    export RUSTUP_HOME=$(cygpath ${RUSTUP_HOME} --windows)
    export CARGO_HOME=$(cygpath ${CARGO_HOME} --windows)
fi

curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path $DEFAULT_HOST_OPTIONS

# This file is not created by default on Windows
echo 'export PATH="$PATH:${CARGO_HOME}/bin"' >> ${CARGO_HOME}/env
echo "export CARGO_NET_GIT_FETCH_WITH_CLI=true" >> ${CARGO_HOME}/env

source ${CARGO_HOME}/env

## libmongocrypt

mkdir native
cd native
curl -sSfO https://s3.amazonaws.com/mciuploads/libmongocrypt/all/master/latest/libmongocrypt-all.tar.gz
tar xzf libmongocrypt-all.tar.gz

if [ "Windows_NT" == "$OS" ]; then
    chmod +x ${MONGOCRYPT_LIB_DIR}/../bin/*.dll
fi

## drivers-tools

if [[ -z "$DRIVERS_TOOLS" ]]; then
    echo >&2 "\$DRIVERS_TOOLS must be set"
    exit 1
fi

rm -rf $DRIVERS_TOOLS
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git $DRIVERS_TOOLS