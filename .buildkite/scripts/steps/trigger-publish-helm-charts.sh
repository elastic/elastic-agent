#!/usr/bin/env bash
#
# Create a dynamic buildkite step that triggers the
# unified-release-publish-helm-charts pipeline.
#
# Required environment variables:
#  - HELM_REPO_ENV
#  - CHART_URL
#

set -eo pipefail

HELM_REPO_ENV=${HELM_REPO_ENV:-"dev"}

if [ -z "$CHART_URL" ] ; then
  echo "CHART_URL could not be found."
  exit 1
fi

cat << EOF
  - label: ":elastic-stack: Publish helm chart"
    trigger: unified-release-publish-helm-charts
    build:
      message: "publish helm-chart for elastic-agent in ${HELM_REPO_ENV}"
      env:
        CHARTS_URL: "${CHART_URL}"
        HELM_REPO_ENV: ${HELM_REPO_ENV}
EOF