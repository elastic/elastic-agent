#!/usr/bin/env bash
set -euo pipefail

function check_es_access() {
  # EC_API_KEY provided by buildkite-vault plugin. See the pipeline step definition.
  if [[ -z "${EC_API_KEY}" ]]; then
    echo "Error: EC_API_KEY is empty" >&2
    exit 1
  fi
}

function ess_up() {
  echo "~~~ Starting ESS Stack"
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  local STACK_VERSION=$1
  local ESS_REGION=${2:-"gcp-us-west2"}
    
  if [ -z "$STACK_VERSION" ]; then
    echo "Error: Specify stack version: ess_up [stack_version]" >&2
    return 1
  fi

  check_es_access

  BUILDKITE_BUILD_CREATOR="${BUILDKITE_BUILD_CREATOR:-"$(get_git_user_email)"}"
  BUILDKITE_BUILD_NUMBER="${BUILDKITE_BUILD_NUMBER:-"0"}"
  BUILDKITE_PIPELINE_SLUG="${BUILDKITE_PIPELINE_SLUG:-"elastic-agent-integration-tests"}"
  
  pushd "${TF_DIR}"    
  terraform init
  terraform apply \
    -auto-approve \
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
  export INTEGRATIONS_SERVER_HOST=$(terraform output -raw integrations_server_endpoint)
  popd
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"  
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  check_es_access
  
  pushd "${TF_DIR}"
  terraform init
  terraform destroy -auto-approve
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

