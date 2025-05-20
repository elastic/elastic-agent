#!/usr/bin/env bash
#
# This script is executed by the automation we are putting in place
# and it requires the git add/commit commands.
#
set -euo pipefail
TARGET_VERSION="${1:?Error: Please provide the target version to update to}"

echo "~~~ Updating to elastic/beats@${TARGET_VERSION}"
mage update:beats "${TARGET_VERSION}"
