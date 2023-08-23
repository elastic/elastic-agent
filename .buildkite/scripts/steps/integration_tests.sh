##!/usr/bin/env bash
 set -euxo pipefail

 source .buildkite/scripts/common.sh

 # PACKAGE
 AGENT_PACKAGE_VERSION=8.10.0 \
 DEV=true \
 EXTERNAL=true \
 PACKAGES=tar.gz \
 PLATFORMS=linux/amd64,linux/arm64 \
 SNAPSHOT=true \
 mage package

 # Run integration tests
 set +e
 AGENT_STACK_VERSION=8.10.0-SNAPSHOT \
 AGENT_VERSION=8.10.0-SNAPSHOT \
 SNAPSHOT=true \
 TEST_INTEG_CLEAN_ON_EXIT=true \
 mage integration:test
 TESTS_EXIT_STATUS=$?
 set -e

 # HTML report
 go install github.com/alexec/junit2html@latest
 junit2html < build/TEST-go-integration.xml > build/TEST-report.html

 exit $TESTS_EXIT_STATUS
