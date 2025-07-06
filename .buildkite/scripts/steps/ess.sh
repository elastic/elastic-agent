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
  #oblt-cli cluster create custom \
  #    --template ess-ea-it \
  #    --cluster-name-prefix ea-hosted-it \
  #    --parameters="{\"GitOps\":\"true\",\"GitHubRepository\":\"${BUILDKITE_REPO}\",\"GitHubCommit\":\"${BUILDKITE_COMMIT}\",\"EphemeralCluster\":\"true\",\"StackVersion\":\"$STACK_VERSION\"}" \
  #    --output-file="${PWD}/cluster-info.json" \
  #    --wait 15

  # Extract the cluster name from the cluster information file
  #CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)
  CLUSTER_NAME=ea-hosted-it-ess-ea--ppknr

  # Store the cluster name as a meta-data
  buildkite-agent meta-data set cluster-name "${CLUSTER_NAME}"

  ess_load_secrets
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"
  # Get the cluster name from the meta-data
  CLUSTER_NAME="$(buildkite-agent meta-data get cluster-name)"

  # Destroy the cluster
  oblt-cli cluster destroy --cluster-name "${CLUSTER_NAME}" --force
}

function ess_load_secrets() {
  echo "~~~ Load secrets ESS Stack"

  # Get the cluster name from the meta-data
  CLUSTER_NAME="$(buildkite-agent meta-data get cluster-name)"
  echo "Cluster name: ${CLUSTER_NAME}"

  # Load the ESS stack secrets
  secrets_file="secrets.env.sh"
  # QUESTION: should we support the case when using the ESS stack in local environment?
  oblt-cli cluster secrets env --cluster-name="${CLUSTER_NAME}" --output-file="${secrets_file}"

  # NOTE: only for debugging purposes
  #       so we know the secrets file has been created
  buildkite-agent artifact upload "$secrets_file"

  # Source the secrets file
  # shellcheck source=/dev/null
  source "${secrets_file}" || rm "$secrets_file"
  rm $secrets_file || true

  # Redact secrets in the output
  for secret_var in ELASTICSEARCH_HOST ELASTICSEARCH_USERNAME ELASTICSEARCH_PASSWORD KIBANA_HOST KIBANA_USERNAME KIBANA_PASSWORD FLEET_URL; do
    secret_value="${!secret_var}"
    if [ -n "$secret_value" ]; then
      echo "$secret_value" | buildkite-agent redactor add
    fi
  done
  # Export the secrets as environment variables
  export ELASTICSEARCH_HOST ELASTICSEARCH_USERNAME ELASTICSEARCH_PASSWORD
  export KIBANA_HOST KIBANA_USERNAME KIBANA_PASSWORD
  # NOTE: I don't think INTEGRATIONS_SERVER_HOST is used in the ESS stack
  export INTEGRATIONS_SERVER_HOST=$FLEET_URL

  echo "smoke test: ESS Stack secrets loaded"
  curl -s -X GET "${ELASTICSEARCH_HOST}/_cluster/health?pretty" -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}
}
