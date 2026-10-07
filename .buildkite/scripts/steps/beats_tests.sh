#!/usr/bin/env bash
set -euo pipefail

#=========================
# NOTE: This entire script is a temporary hack until we have buildkite set up on the beats repo.
# until then, we need some kind of serverless integration tests, hence this script, which just builds the beats checked out in the beats submodule,
# and runs the serverless integration suite against different beats
# After buildkite is set up on beats, this file/PR should be reverted.
#==========================

source .buildkite/scripts/common.sh
STACK_PROVISIONER="${1:-"serverless"}"

# We don't want any metadata from .package-version in these tests
export USE_PACKAGE_VERSION=false

# Build the beats pinned by the submodule, not the tip of a beats branch. The latter can be on a different version than
# the one the integration runner expects, which fails the build confusingly. With the submodule, a mismatch after a
# version bump shows up in the bump PR itself.
BEATS_DIR="$(pwd)/beats"

run_test_for_beat(){
    export GOFLAGS='-buildvcs=false'
    local beat_name=$1

    #build
    export WORKSPACE="${BEATS_DIR}/x-pack/${beat_name}"
    pushd $WORKSPACE
    whoami
    ls -la
    unset BEAT_VERSION # prevent EA workspace version from leaking into the Beats build
    SNAPSHOT=true PLATFORMS=linux/amd64 PACKAGES=tar.gz,zip mage package
    popd

    #run
    export AGENT_BUILD_DIR="${BEATS_DIR}/x-pack/${beat_name}/build/distributions"
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

echo "testing filebeat..."
run_test_for_beat filebeat
