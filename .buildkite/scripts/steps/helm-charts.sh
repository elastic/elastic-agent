#!/usr/bin/env bash
# This script runs the helm-charts for the given environment
# uploads the package to GCS and
# triggers the unified-release-publish-helm-charts pipeline.
#
# Required environment variables:
#  - HELM_REPO_ENV
#  - SNAPSHOT

# shellcheck disable=SC1091
source .buildkite/scripts/common.sh

set -euo pipefail

echo "--- validate environment variables"
if [[ "${SNAPSHOT}" == "true" && "${HELM_REPO_ENV}" == "prod" ]]; then
  echo "SNAPSHOT=true is not allowed in prod"
  exit 1
fi

echo "--- mage helm:package"
mage helm:package

echo "--- upload package tests"
STORAGE=elastic-agent-helm-chart
gcloud storage cp elastic-agent-*.tgz gs://"${STORAGE}" --print-created-message

echo "--- load trigger pipeline"
HELM_CHART_FILE=$(ls -1 elastic-agent-*.tgz)
CHART_URL="https://storage.googleapis.com/${STORAGE}/${HELM_CHART_FILE}"
export CHART_URL
.buildkite/scripts/steps/trigger-publish-helm-charts.sh
.buildkite/scripts/steps/trigger-publish-helm-charts.sh | buildkite-agent pipeline upload
