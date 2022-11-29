#!/bin/bash

set -o errexit

if [[ -z "$TAG" ]]; then
	>&2 echo "\$TAG must be set to the git tag of the release (not including the crate)"
	exit 1
fi

if [[ -z "$TOKEN" ]]; then
	>&2 echo "\$TOKEN must be set to the crates.io authentication token"
	exit 1
fi


if [[ ! "$CRATE" =~ ^(mongocrypt|mongocrypt-sys)$ ]]; then
	>&2 echo '$CRATE must be set to the crate to publish (mongocrypt or mongocrypt-sys)'
	exit 1
fi

cd $(dirname $0)
git fetch origin tag $CRATE-$TAG --no-tags
git checkout $CRATE-$TAG

cd $CRATE
cargo publish --token $TOKEN "$@"