#!/usr/bin/env bash
set -euo pipefail

# `oblt-cli cluster create --wait` returns as soon as the cluster config lands on
# the observability-test-environments default branch, but the credentials secret
# is published by a later step of the cluster-manager workflow and has been
# observed to lag by several minutes, so ess_load_secrets polls for it.
ESS_SECRETS_TIMEOUT_SECONDS="${ESS_SECRETS_TIMEOUT_SECONDS:-600}"
ESS_SECRETS_POLL_INTERVAL_SECONDS="${ESS_SECRETS_POLL_INTERVAL_SECONDS:-15}"

function ess_up() {
  : "${1:?Error: Specify stack version: ess_up [stack_version] [stack_build_id]}"

  echo "~~~ Starting ESS Stack"
  local STACK_VERSION=$1
  local STACK_BUILD_ID=${2:-""}

  # Build the oblt-cli command with conditional ElasticAgentDockerImage parameter
  local oblt_cmd=(
    oblt-cli cluster create custom
    --template ess-ea-it-build-id
    --cluster-name-prefix hosted
    --output-file="${PWD}/cluster-info.json"
    --wait 20
    --parameter "StackVersion=$STACK_VERSION"
    --parameter "ExpireInHours=2"
  )

  # Snapshot stacks need explicit image tags. Released stacks can be created
  # from StackVersion alone until the next snapshot build is available.
  if [ -n "${STACK_BUILD_ID}" ]; then
    oblt_cmd+=(--parameter "StackBuildId=${STACK_BUILD_ID}")
  fi

  if [ -n "${INTEGRATION_SERVER_DOCKER_IMAGE:-}" ]; then
    oblt_cmd+=(--parameter "ElasticAgentDockerImage=${INTEGRATION_SERVER_DOCKER_IMAGE}")
  fi

  # Create a cluster with the specified stack version and store the cluster information in a file
  "${oblt_cmd[@]}"

  # Extract the cluster name from the cluster information file
  CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)
  if [ -z "${CLUSTER_NAME}" ] || [ "${CLUSTER_NAME}" = "null" ]; then
    echo "Error: Failed to extract ClusterName from cluster-info.json" >&2
    return 1
  fi

  # NOTE: the shared `cluster-name` meta-data is only written by the shared
  # ess_start_oblt-cli.sh wrapper. Per-step retries must not overwrite it,
  # otherwise the global cleanup step would destroy the retry's cluster and
  # leak the shared one. `ess_load_secrets` and `ess_down` read the local
  # cluster-info.json first, so the retry path doesn't need meta-data.

  # However, store retry cluster names in a separate metadata key so they can
  # be cleaned up by a dedicated cleanup step if the EXIT trap fails (e.g., timeout)
  if [ "${BUILDKITE_RETRY_COUNT:-0}" -gt 0 ]; then
    METADATA_PREFIX="${METADATA_PREFIX:-""}"
    local retry_key="${METADATA_PREFIX}retry-cluster-${BUILDKITE_STEP_ID}-${BUILDKITE_RETRY_COUNT}"
    echo "Storing retry cluster name in metadata: $retry_key = $CLUSTER_NAME"
    buildkite-agent meta-data set "$retry_key" "$CLUSTER_NAME" || true
  fi

  ess_load_secrets
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"
  METADATA_PREFIX="${METADATA_PREFIX:-""}"
  local CLUSTER_NAME=""

  # Prefer the local cluster-info.json from this step's own ess_up, so we don't
  # destroy a cluster created by a parallel step (the shared `cluster-name`
  # meta-data is a global key that any ess_up writer can overwrite).
  if [ -f "${PWD}/cluster-info.json" ]; then
    CLUSTER_NAME="$(jq -r '.ClusterName' "${PWD}/cluster-info.json" 2>/dev/null || true)"
    if [ "${CLUSTER_NAME}" = "null" ]; then
      CLUSTER_NAME=""
    fi
  fi
  if [ -z "${CLUSTER_NAME}" ]; then
    CLUSTER_NAME="$(buildkite-agent meta-data get "${METADATA_PREFIX}cluster-name" 2>/dev/null || true)"
  fi
  if [ -z "${CLUSTER_NAME}" ]; then
    echo "No cluster-name found; nothing to destroy."
    return 0
  fi

  # Destroy the cluster. Soft-fail: the cluster is ephemeral and will auto-expire.
  if ! oblt-cli cluster destroy --cluster-name "${CLUSTER_NAME}" --force; then
    echo "Warning: failed to destroy cluster '${CLUSTER_NAME}' - ephemeral cluster will auto-expire." >&2
    return 0
  fi
}

# Returns 0 when oblt-cli failed because GCP Secret Manager does not have the
# cluster env secret yet (gRPC NotFound). Other failures should not be polled.
function ess_secrets_not_found_yet() {
  grep -qiE 'code = NotFound|not found or has no versions' <<<"$1"
}

function ess_load_secrets() {
  echo "~~~ Loading ESS Stack secrets"

  METADATA_PREFIX="${METADATA_PREFIX:-""}"
  local CLUSTER_NAME=""

  # Prefer the local cluster-info.json from this step's own ess_up, so we don't
  # read secrets from a cluster created by a parallel step (the shared
  # `cluster-name` meta-data is a global key that any ess_up writer can overwrite).
  if [ -f "${PWD}/cluster-info.json" ]; then
    CLUSTER_NAME="$(jq -r '.ClusterName' "${PWD}/cluster-info.json" 2>/dev/null || true)"
    if [ "${CLUSTER_NAME}" = "null" ]; then
      CLUSTER_NAME=""
    fi
  fi
  if [ -z "${CLUSTER_NAME}" ]; then
    CLUSTER_NAME="$(buildkite-agent meta-data get "${METADATA_PREFIX}cluster-name")"
  fi

  # Load the ESS stack secrets, polling until the cluster-manager workflow has
  # published them (see the note at the top of this file). Capture output so
  # retry attempts stay to one line; dump the last oblt-cli output only when
  # giving up. Retry only GCP NotFound (secret not published yet); fail fast
  # on auth, permission, or other errors.
  local secrets_file="secrets.env.sh"
  local deadline=$((SECONDS + ESS_SECRETS_TIMEOUT_SECONDS))
  local attempt=0
  local last_output=""
  local last_rc=0
  while true; do
    attempt=$((attempt + 1))
    last_rc=0
    last_output="$(oblt-cli cluster secrets env --cluster-name="${CLUSTER_NAME}" --output-file="${secrets_file}" 2>&1)" || last_rc=$?
    if [ "${last_rc}" -eq 0 ]; then
      if [ -n "${last_output}" ]; then
        echo "${last_output}"
      fi
      break
    fi
    if ! ess_secrets_not_found_yet "${last_output}"; then
      echo "${last_output}" >&2
      echo "Error: oblt-cli cluster secrets env failed for cluster '${CLUSTER_NAME}' (exit=${last_rc}); not retrying" >&2
      return 1
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "${last_output}" >&2
      echo "Error: oblt-cli cluster secrets env failed for cluster '${CLUSTER_NAME}' after ${ESS_SECRETS_TIMEOUT_SECONDS}s and ${attempt} attempts (last exit=${last_rc})" >&2
      return 1
    fi
    echo "Secrets for cluster '${CLUSTER_NAME}' are not available yet (attempt ${attempt}, exit=${last_rc}); retrying in ${ESS_SECRETS_POLL_INTERVAL_SECONDS}s..." >&2
    sleep "${ESS_SECRETS_POLL_INTERVAL_SECONDS}"
  done

  # Source the secrets file with allexport to make variables available outside the function
  local src_rc=0
  set -a
  # shellcheck source=/dev/null
  source "${secrets_file}" || src_rc=$?
  set +a
  rm "$secrets_file" || true
  if [ "$src_rc" -ne 0 ]; then
    echo "Error: Failed to source secrets file (exit code ${src_rc})" >&2
    return 1
  fi

  # Print loaded variable names for debugging (not values)
  env | grep -E '^(ELASTICSEARCH|KIBANA|FLEET_SERVER|INTEGRATIONS_SERVER)' | cut -d= -f1 || true
}
