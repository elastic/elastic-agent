#!/usr/bin/env bash
set -euo pipefail

function ess_up() {
  echo "~~~ Starting ESS Stack"
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  local STACK_VERSION=$1
  local STACK_BUILD_ID=${2:-""}
  local ESS_REGION=${3:-"gcp-us-west2"}
    
  if [ -z "$STACK_VERSION" ]; then
    echo "Error: Specify stack version: ess_up [stack_version]" >&2
    return 1
  fi

  BUILDKITE_BUILD_CREATOR="${BUILDKITE_BUILD_CREATOR:-"$(get_git_user_email)"}"
  BUILDKITE_BUILD_NUMBER="${BUILDKITE_BUILD_NUMBER:-"0"}"
  BUILDKITE_PIPELINE_SLUG="${BUILDKITE_PIPELINE_SLUG:-"elastic-agent-integration-tests"}"
  
  pushd "${TF_DIR}"    
  terraform init
  terraform apply \
    -auto-approve \
    -var="stack_version=${STACK_VERSION}" \
    -var="stack_build_id=${STACK_BUILD_ID}" \
    -var="ess_region=${ESS_REGION}" \
    -var="creator=${BUILDKITE_BUILD_CREATOR}" \
    -var="buildkite_id=${BUILDKITE_BUILD_NUMBER}" \
    -var="pipeline=${BUILDKITE_PIPELINE_SLUG}"

  export ELASTICSEARCH_HOST=$(terraform output -raw es_host)
  export ELASTICSEARCH_USERNAME=$(terraform output -raw es_username)
  export ELASTICSEARCH_PASSWORD=$(terraform output -raw es_password)
  export KIBANA_HOST=$(terraform output -raw kibana_endpoint)
  export KIBANA_USERNAME=$ELASTICSEARCH_USERNAME
  export KIBANA_PASSWORD=$ELASTICSEARCH_PASSWORD
  export INTEGRATIONS_SERVER_HOST=$(terraform output -raw integrations_server_endpoint)
  popd
}

function wait_for_stack() {
  local max_attempts=${1:-60}
  local sleep_seconds=${2:-10}

  echo "~~~ Waiting for ESS Stack to be reachable"

  local attempt=0
  while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))
    echo "Attempt $attempt/$max_attempts: checking stack connectivity..."

    local es_ok=false
    local kibana_ok=false

    if curl -sf -u "${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}" \
        --max-time 10 \
        "${ELASTICSEARCH_HOST}" > /dev/null 2>&1; then
      es_ok=true
    fi

    if curl -sf -u "${KIBANA_USERNAME}:${KIBANA_PASSWORD}" \
        --max-time 10 \
        "${KIBANA_HOST}/api/status" > /dev/null 2>&1; then
      kibana_ok=true
    fi

    if $es_ok && $kibana_ok; then
      echo "Stack is reachable (Elasticsearch: OK, Kibana: OK)"
      return 0
    fi

    echo "Not ready yet (Elasticsearch: $es_ok, Kibana: $kibana_ok). Retrying in ${sleep_seconds}s..."
    sleep "$sleep_seconds"
  done

  echo "Error: Stack did not become reachable after $((max_attempts * sleep_seconds))s" >&2
  return 1
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"
  local ESS_REGION=${1:-"gcp-us-west2"}
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  
  pushd "${TF_DIR}"
  terraform init
  terraform destroy -auto-approve \
    -var="ess_region=${ESS_REGION}"
  popd
}

function get_git_user_email() {
  if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo "unknown"  
    return
  fi

  local email
  email=$(git config --get user.email)
  
  if [ -z "$email" ]; then
    echo "unknown"  
  else
    echo "$email"
  fi
}

