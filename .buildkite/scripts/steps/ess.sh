#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

# 
function ess_up() {
  echo "~~~ Staring ESS Stack"
  # Delete
  set -x
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  local STACK_VERSION=$1
  local ESS_REGION=${2:-"gcp-us-west2"}
    
  if [ -z "$STACK_VERSION" ]; then
    echo "Error: Specify stack version: ess_up [stack_version]" >&2
    return 1
  fi

  local EC_API_KEY=$(retry 5 vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod)
  
  if [[ -z "${EC_API_KEY}" ]]; then
    echo "Error: Failed to get EC API key from vault" >&2
    exit 1
  fi

  BUILDKITE_BUILD_CREATOR="${BUILDKITE_BUILD_CREATOR:-"$(get_git_user_email)"}"
  BUILDKITE_BUILD_NUMBER="${BUILDKITE_BUILD_NUMBER:-"0"}"
  BUILDKITE_PIPELINE_SLUG="${BUILDKITE_PIPELINE_SLUG:-"elastic-agent-integration-tests"}"
  
  pushd "${TF_DIR}"
  trap 'popd >/dev/null' EXIT
  
  terraform init
  
  terraform apply \
    -var="stack_version=${STACK_VERSION}" \
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

  # Delete
  sex +x
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"
  set -x
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  local EC_API_KEY=$(retry 5 vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod)
  
  pushd "${TF_DIR}"
  trap 'popd >/dev/null' EXIT

  terraform destroy -auto-approve
  set +x
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
