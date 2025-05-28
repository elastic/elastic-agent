#!/usr/bin/env bash

# This script provisions an Elasticsearch cluster using oblt-cli.
#
# Arguments:
# - ${1}: cluster_name_prefix: A prefix to use for the cluster name (required)
# - ${2}: target: Target environment to deploy (qa, staging, production) (optional, default: "qa")
# - ${3}: region: What region to deploy to (optional, default: "aws-eu-west-1")
#
# Usage:
# ./provision-cluster.sh "cluster-name-prefix"
#
# Output:
# cluster_name

set -euo pipefail

BUILDKITE=${BUILDKITE:-}

cluster_name_prefix=${1}
ENVIRONMENT=${2:-qa}
REGION=${3:-aws-eu-west-1}
create_output_file="${PWD}/cluster.json"
echo "[INFO] Creating serverless cluster" >&2
oblt-cli cluster create custom \
  --cluster-name-prefix "${cluster_name_prefix}" \
  --template "serverless-elastic-agent" \
  --parameters "{\"GitHubRepository\": \"elastic/elastic-agent\", \"Target\": \"$ENVIRONMENT\", \"Region\": \"$REGION\"}" \
  --disable-banner \
  --wait 15 \
  --output-file "${create_output_file}" >&2

echo "[DEBUG] Created file: ${create_output_file}" >&2

cluster_name=$(jq -r '.ClusterName' < "${create_output_file}")

echo "[DEBUG] Cluster name: ${cluster_name}" >&2

oblt_pr_link="https://github.com/elastic/observability-test-environments/pulls?q=is%3Apr+${cluster_name}"

if [ -n "$BUILDKITE" ]; then
  buildkite-agent annotate "observability-test-environments PR: ${oblt_pr_link}" --style "info" --context "ctx-oblt-cli-${cluster_name}"
  buildkite-agent meta-data set "cluster-name" "${cluster_name}"
fi

echo "[INFO] Waiting for cluster ${cluster_name} to be created.\
  You can find the the status of your request in ${oblt_pr_link}" >&2

echo "${cluster_name}"