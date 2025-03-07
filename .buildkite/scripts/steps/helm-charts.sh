#!/usr/bin/env bash
# This script runs the helm-charts for the given environment
# STAGING OR SNAPSHOT
# And Upload the package to GCS

# shellcheck disable=SC1091
source .buildkite/scripts/common.sh

set -euo pipefail

echo "--- mage helm:package"
SNAPSHOT=true mage helm:package

echo "--- upload package tests"
gcloud storage cp elastic-agent-*.tgz gs://elastic-agent-helm-chart --print-created-message

# NOTE: store the name of the artifact. This will be used in the next step to download the artifact
HELM_CHART_FILE=$(ls -1 elastic-agent-*.tgz)
buildkite-agent meta-data set "HELM_CHART" "$HELM_CHART_FILE"
