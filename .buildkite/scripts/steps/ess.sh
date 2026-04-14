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
  if [ -z "${CLUSTER_NAME}" ] || [ "${CLUSTER_NAME}" = "null" ]; then
    echo "Error: Failed to extract ClusterName from cluster-info.json" >&2
    return 1
  fi

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

function get_cluster_secrets {
  echo "Getting cluster secrets cluster-state"
  oblt-cli cluster secrets env --cluster-name="${1}" --output-file="${2}"
}

function ess_load_secrets() {
  set -x
  echo "~~~ Loading ESS Stack secrets"

  METADATA_PREFIX="${METADATA_PREFIX:-""}"
  # Get the cluster name from the meta-data
  CLUSTER_NAME="$(buildkite-agent meta-data get "${METADATA_PREFIX}cluster-name")"

  echo "Searching the ESS stack secrets"
  local secrets_file="secrets.env.sh"

  MAX_ATTEMPTS=10
  attempt=0
  until get_cluster_secrets "${CLUSTER_NAME}" "${secrets_file}";
  do
    attempt=$((attempt+1))
    if [[ "${attempt}" -gt "${MAX_ATTEMPTS}" ]]; then
      echo "[ERROR] Failed to get cluster secrets after ${MAX_ATTEMPTS} attempts.\
        Your request to create the cluster ${CLUSTER_NAME} might have failed" >&2
      exit 1
    fi
    sleep 60
    echo "[INFO] Retrying to get cluster secrets" >&2
  done

  echo "Loading the ESS stack secrets"
  local src_rc=0
  # Source the secrets file
  # shellcheck source=/dev/null
  source "${secrets_file}" || src_rc=$?
  rm "$secrets_file" || true
  if [ "$src_rc" -ne 0 ]; then
    echo "Error: Failed to source secrets file (exit code ${src_rc})" >&2
    return 1
  fi

  set +x

  # Print loaded variable names for debugging (not values)
  env | grep -E '^(ELASTICSEARCH|KIBANA|FLEET_SERVER|INTEGRATIONS_SERVER|AGENT_POLICY_ID)' | cut -d= -f1
}
