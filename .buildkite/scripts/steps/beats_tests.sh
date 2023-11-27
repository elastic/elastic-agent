#!/usr/bin/env bash
set -euo pipefail

#=========================
# NOTE: This entire script is a temporary hack until we have buildkite set up on the beats repo.
# until then, we need some kind of serverless integration tests, hence this script, which just clones the beats repo,
# and runs the serverless integration suite against different beats
# After buildkite is set up on beats, this file/PR should be reverted.
#==========================

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
    TEST_INTEG_CLEAN_ON_EXIT=true TEST_PLATFORMS="linux/amd64" STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage integration:testBeatServerless $beat_name
    TESTS_EXIT_STATUS=$?
    set -e

    return $TESTS_EXIT_STATUS
}
#run mage before setup, since this will install go and mage
#the setup scripts will do a few things that assume we're running out of elastic-agent and will break things for beats, so run before we do actual setup
mage -l

mkdir -p build
cd build

git clone --filter=tree:0 git@github.com:elastic/beats.git
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

echo "testing metricbeat..."
run_test_for_beat metricbeat



echo "testing filebeat..."
run_test_for_beat filebeat



echo "testing auditbeat..."
run_test_for_beat auditbeat
