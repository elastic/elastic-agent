#!/usr/bin/env bash
#
# Create a dynamic buildkite step with the HELM_CHART returned by the
# script .buildkite/scripts/steps/helm-charts.sh.
# This step will trigger the unified-release-publish-helm-charts pipeline.
#
# Required environment variables:
#  - HELM_REPO_ENV
#

set -eo pipefail

HELM_REPO_ENV=${HELM_REPO_ENV:-"dev"}

## Fetch the URL from .buildkite/scripts/steps/helm-charts.sh
CHART_URL=$(buildkite-agent meta-data get "CHART_URL")

if [ -z "$CHART_URL" ] ; then
  echo "CHART_URL metadata could not be loaded."
  exit 1
fi

cat << EOF
  - label: ":elastic-stack: Publish helm chart"
    trigger: unified-release-publish-helm-charts
    build:
      message: "publish helm-chart for elastic-agent in ${HELM_REPO_ENV}"
      env:
        CHARTS_URL: "${CHARTS_URL}"
        HELM_REPO_ENV: ${HELM_REPO_ENV}
EOF