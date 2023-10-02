#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

# PACKAGE
<<<<<<< HEAD
DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64 PACKAGES=tar.gz mage package
=======
AGENT_PACKAGE_VERSION="${OVERRIDE_AGENT_PACKAGE_VERSION}" DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package
>>>>>>> 35dbbdea9b (Add Windows support to integration testing runner (#2941))

# Run integration tests
set +e
TEST_INTEG_CLEAN_ON_EXIT=true SNAPSHOT=true mage integration:test
TESTS_EXIT_STATUS=$?
set -e

# HTML report
go install github.com/alexec/junit2html@latest
junit2html < build/TEST-go-integration.xml > build/TEST-report.html

exit $TESTS_EXIT_STATUS
