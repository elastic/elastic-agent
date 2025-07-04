#!/usr/bin/env bash
set -euo pipefail

function ess_up() {
  echo "~~~ Starting ESS Stack"
  local STACK_VERSION=$1
  local ESS_REGION=${2:-"gcp-us-west2"}
    
  if [ -z "$STACK_VERSION" ]; then
    echo "Error: Specify stack version: ess_up [stack_version]" >&2
    return 1
  fi

  # Create a cluster with the specified stack version and store the cluster information in a file
  oblt-cli cluster create custom \
      --template ess-ea-it \
      --cluster-name-prefix ea-hosted-it \
      --parameters="{\"GitOps\":\"true\",\"GitHubRepository\":\"${BUILDKITE_REPO}\",\"GitHubCommit\":\"${BUILDKITE_COMMIT}\",\"EphemeralCluster\":\"true\",\"StackVersion\":\"$STACK_VERSION\"}" \
      --output-file="${PWD}/cluster-info.json" \
      --wait 15

  # Extract the cluster name from the cluster information file
  CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)

  # Store the cluster name as a meta-data
  buildkite-agent meta-data set cluster-name "${CLUSTER_NAME}"

  # Load the ESS stack secrets
  # QUESTION: should we support the case when using the ESS stack in local environment?
  oblt-cli cluster secrets env --cluster-name="${CLUSTER_NAME}" --output-file="secrets.env"

  # Source the secrets file
  source "secrets.env" || rm "secrets.env"
  rm secrets.env || true
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"
  # Get the cluster name from the meta-data
  CLUSTER_NAME="$(buildkite-agent meta-data get cluster-name)"

  # Destroy the cluster
  oblt-cli cluster destroy --cluster-name "${CLUSTER_NAME}" --force
}
