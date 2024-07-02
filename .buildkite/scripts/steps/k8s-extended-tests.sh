#!/bin/bash
set -euo pipefail

source .buildkite/scripts/common.sh

export PATH=$HOME/bin:${PATH}
source .buildkite/scripts/install-kubectl.sh
source .buildkite/scripts/install-kind.sh

# Run k8s integration tests
set +e
TEST_INTEG_CLEAN_ON_EXIT=true INSTANCE_PROVISIONER=kind STACK_PROVISIONER=stateful EXTERNAL=true mage integration:kubernetes
TESTS_EXIT_STATUS=$?
set -e

# HTML report
outputXML="build/TEST-go-integration.xml"

if [ -f "$outputXML" ]; then
  go install github.com/alexec/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS
