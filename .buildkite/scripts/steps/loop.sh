#!/usr/bin/env bash
set -euo pipefail

GROUP_NAME=$1
TEST_SUDO=$2

max_attempts=5
status=0
for i in $(seq 1 $max_attempts); do
    echo "Attempt $i"
    .buildkite/scripts/steps/integration_tests_tf.sh $GROUP_NAME $TEST_SUDO
    if [ $? -ne 0 ]; then
        status=1
    fi
done

exit $status
