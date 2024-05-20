#!/bin/bash

set -o errexit

source ./.evergreen/configure-rust.sh

. ${DRIVERS_TOOLS}/.evergreen/find-python3.sh
PYTHON=$(find_python3)

if [[ -f "semgrep/bin/activate" ]]; then
    echo 'using existing virtualenv'
    . semgrep/bin/activate
else
    echo 'Creating new virtualenv'  
    ${PYTHON} -m venv semgrep
    echo 'Activating new virtualenv'
    . semgrep/bin/activate
    python3 -m pip install semgrep
fi

OPTS="--config p/rust --exclude-rule rust.lang.security.unsafe-usage.unsafe-usage"

# Generate a SARIF report
semgrep ${OPTS} --sarif > mongo-rust-libmongocrypt.json.sarif
# And human-readable output
semgrep ${OPTS} --error