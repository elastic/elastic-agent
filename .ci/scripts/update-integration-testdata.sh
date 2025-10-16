#!/usr/bin/env bash
#
# This script is executed by the automation we are putting in place
# and it requires the git add/commit commands.
#
set -euo pipefail

echo "~~~ Updating integration tests testdata"
mage integration:buildKubernetesTestData
