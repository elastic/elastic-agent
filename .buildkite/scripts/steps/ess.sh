#!/usr/bin/env bash
set -euo pipefail

function ess_up() {
  echo "~~~ Starting ESS Stack"
  local STACK_VERSION=$1

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
  METADATA_PREFIX="${METADATA_PREFIX:-""}"
  buildkite-agent meta-data set "${METADATA_PREFIX}cluster-name" "${CLUSTER_NAME}"

  ess_load_secrets
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"
  METADATA_PREFIX="${METADATA_PREFIX:-""}"
  # Get the cluster name from the meta-data
  CLUSTER_NAME="$(buildkite-agent meta-data get "${METADATA_PREFIX}cluster-name")"

  # Destroy the cluster
  oblt-cli cluster destroy --cluster-name "${CLUSTER_NAME}" --force
}

function ess_load_secrets() {
  echo "~~~ Loading ESS Stack secrets"

  METADATA_PREFIX="${METADATA_PREFIX:-""}"
  # Get the cluster name from the meta-data
  CLUSTER_NAME="$(buildkite-agent meta-data get "${METADATA_PREFIX}cluster-name")"

  # Load the ESS stack secrets
  local secrets_file="secrets.env.sh"
  oblt-cli cluster secrets env --cluster-name="${CLUSTER_NAME}" --output-file="${secrets_file}"

  # Source the secrets file
  # shellcheck source=/dev/null
  source "${secrets_file}" || rm "$secrets_file"
  rm "$secrets_file" || true

  # Print loaded variable names for debugging (not values)
  env | grep -E '^(ELASTICSEARCH|KIBANA|FLEET_SERVER|INTEGRATIONS_SERVER|AGENT_POLICY_ID)' | cut -d= -f1
}
