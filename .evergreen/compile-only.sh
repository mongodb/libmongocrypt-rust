#!/bin/bash

set -o errexit

source ./.evergreen/configure-rust.sh

cd $TARGET_DIR
cargo build