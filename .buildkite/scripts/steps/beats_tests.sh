#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh
#run before setup, since this will install go and mage
# the setup scripts will do a few things that assume we care about agent, so run before we do actual setup
mage -l

mkdir -p build
cd build

git clone git@github.com:elastic/beats.git

#cd beats/x-pack/metricbeat
export WORKSPACE=beats/x-pack/metricbeat

SNAPSHOT=true PLATFORMS=linux/amd64,windows/amd64 PACKAGES=tar.gz,zip mage package
STACK_PROVISIONER="${1:-"serverless"}"

cd ..

export AGENT_BUILD_DIR=build/beats/x-pack/metricbeat/build/distributions
export WORKSPACE=$(pwd)

set +e
TEST_INTEG_CLEAN_ON_EXIT=true TEST_PLATFORMS="linux/amd64" STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage integration:testBeatServerless metricbeat
TESTS_EXIT_STATUS=$?
set -e

exit $TESTS_EXIT_STATUS