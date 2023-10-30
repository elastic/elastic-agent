#!/usr/bin/env bash
set -euo pipefail
set -x

source .buildkite/scripts/common.sh
#run before setup, since this will install go and mage
# the setup scripts will do a few things that assume we care about agent, so run before we do actual setup
mage -l

mkdir -p build
pushd build

git clone git@github.com:elastic/beats.git

#cd beats/x-pack/metricbeat
export WORKSPACE=beats/x-pack/metricbeat

SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package

popd

export AGENT_BUILD_DIR=build/beats/x-pack/metricbeat/build/distributions

set +e
AGENT_VERSION="${OVERRIDE_TEST_AGENT_VERSION}" TEST_INTEG_CLEAN_ON_EXIT=true STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage integration:testBeatServerless
TESTS_EXIT_STATUS=$?
set -e
