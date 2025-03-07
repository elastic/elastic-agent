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
STORAGE=elastic-agent-helm-chart
gcloud storage cp elastic-agent-*.tgz gs://"${STORAGE}" --print-created-message

# NOTE: store the artifact public url.
#       This will be used in .buildkite/scripts/steps/trigger-publish-helm-charts.sh
HELM_CHART_FILE=$(ls -1 elastic-agent-*.tgz)
buildkite-agent meta-data set "CHART_URL" "https://storage.googleapis.com/${STORAGE}/${HELM_CHART_FILE}"
