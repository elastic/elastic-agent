#!/bin/bash
set -euo pipefail

source .buildkite/scripts/install-kubectl.sh
source .buildkite/scripts/install-kind.sh

make -C deploy/kubernetes test