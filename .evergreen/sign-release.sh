#!/bin/bash

set -o errexit
set +x

if [[ -z "$CRATE" ]]; then
    echo >&2 "CRATE is required"
    exit 1
fi
if [[ -z "$ARTIFACTORY_PASSWORD" ]]; then
    echo >&2 "ARTIFACTORY_PASSWORD is required"
    exit 1
fi
if [[ -z "$ARTIFACTORY_USERNAME" ]]; then
    echo >&2 "ARTIFACTORY_USERNAME is required"
    exit 1
fi
if [[ -z "$GARASIGN_USERNAME" ]]; then
    echo >&2 "GARASIGN_USERNAME is required"
    exit 1
fi
if [[ -z "$GARASIGN_PASSWORD" ]]; then
    echo >&2 "GARASIGN_PASSWORD is required"
    exit 1
fi

CRATE_VERSION=$(cargo metadata --format-version=1 --no-deps | jq --raw-output '.packages[0].version')

echo "${ARTIFACTORY_PASSWORD}" | docker login --password-stdin --username ${ARTIFACTORY_USERNAME} artifactory.corp.mongodb.com

echo "GRS_CONFIG_USER1_USERNAME=${GARASIGN_USERNAME}" >> "signing-envfile"
echo "GRS_CONFIG_USER1_PASSWORD=${GARASIGN_PASSWORD}" >> "signing-envfile"

docker run \
  --env-file=signing-envfile \
  --rm \
  -v $(pwd):$(pwd) \
  -w $(pwd) \
  artifactory.corp.mongodb.com/release-tools-container-registry-local/garasign-gpg \
  /bin/bash -c "gpgloader && gpg --yes -v --armor -o ${CRATE}-${CRATE_VERSION}.sig --detach-sign target/package/${CRATE}-${CRATE_VERSION}.crate"

rm signing-envfile