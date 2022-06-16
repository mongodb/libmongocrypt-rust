#!/bin/bash

set -o errexit

source ./.evergreen/configure-rust.sh

cd mongocrypt-sys
cargo test