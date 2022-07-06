#!/bin/bash

set -o errexit

source ./.evergreen/configure-rust.sh

cd mongocrypt
# The test executable has a path like 'target/debug/deps/mongocrypt-661ed156b0be8130', so we scrape it from compiler output
TEST_BIN=$(cargo build -q --tests --message-format json | sed -n 's/^.*"executable":"\(.*mongocrypt-.*\)",.*$/\1/p')
valgrind --leak-check=yes --error-exitcode=1 $TEST_BIN