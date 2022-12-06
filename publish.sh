#!/bin/bash

set -o errexit

if [[ -z "$VERSION" ]]; then
	>&2 echo "\$VERSION must be set to the git tag of the release, not including the crate name"
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
git fetch origin tag $CRATE-$VERSION --no-tags
git checkout $CRATE-$VERSION

cd $CRATE
cargo publish --token $TOKEN "$@"

git checkout main