#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh
STACK_PROVISIONER="${1:-"serverless"}"

run_test_for_beat(){
    local beat_name=$1
    
    #build
    export WORKSPACE="build/beats/x-pack/${beat_name}"
    SNAPSHOT=true PLATFORMS=linux/amd64 PACKAGES=tar.gz,zip mage package

    #run
    export AGENT_BUILD_DIR="build/beats/x-pack/${beat_name}/build/distributions"
    export WORKSPACE=$(pwd)

    set +e
    TEST_INTEG_CLEAN_ON_EXIT=true TEST_PLATFORMS="linux/amd64" STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage integration:testBeatServerless metricbeat
    TESTS_EXIT_STATUS=$?
    set -e

    return $TESTS_EXIT_STATUS
}
#run mage before setup, since this will install go and mage
#the setup scripts will do a few things that assume we're running out of elastic-agent and will break things for beats, so run before we do actual setup
mage -l

mkdir -p build
cd build

git clone git@github.com:elastic/beats.git
cd ..

# export WORKSPACE=beats/x-pack/metricbeat

# SNAPSHOT=true PLATFORMS=linux/amd64,windows/amd64 PACKAGES=tar.gz,zip mage package


# cd ..

# export AGENT_BUILD_DIR=build/beats/x-pack/metricbeat/build/distributions
# export WORKSPACE=$(pwd)

# set +e
# TEST_INTEG_CLEAN_ON_EXIT=true TEST_PLATFORMS="linux/amd64" STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage integration:testBeatServerless metricbeat
# TESTS_EXIT_STATUS=$?
# set -e

# exit $TESTS_EXIT_STATUS

if ! run_test_for_beat metricbeat; then
    exit $?
fi

if ! run_test_for_beat filebeat; then
    exit $?
fi


