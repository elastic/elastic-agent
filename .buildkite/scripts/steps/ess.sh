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

function set_default_number_of_replicas() {
  if [ -z "$ELASTICSEARCH_HOST" ]; then
    echo "Error: Elasticsearch hostname not specified via ELASTICSEARCH_HOST environment variable"
    return 3
  fi

  if [ -z "$ELASTICSEARCH_USERNAME" ]; then
    echo "Error: Elasticsearch username not specified via ELASTICSEARCH_USERNAME environment variable"
    return 4
  fi

  if [ -z "$ELASTICSEARCH_PASSWORD" ]; then
    echo "Error: Elasticsearch password not specified via ELASTICSEARCH_PASSWORD environment variable"
    return 5
  fi

  resp=$(curl \
    -s \
    --fail-with-body \
    -X PUT \
    -u "${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}" \
    -H "Content-Type: application/json" \
    -d '{
      "index_patterns": ["*"],
      "template": {
        "settings": {
          "number_of_replicas": 0
        }
      }
    }'\
    "${ELASTICSEARCH_HOST}/_index_template/global_default_replicas")

  echo "$resp"

  # Parse response body for any errors
  num_errors=$(echo "$resp" | jq '.items[].statusCode | select(.>=400)' | wc -l)
  if [ "$num_errors" -gt 0 ]; then
    echo "$resp"
    return 6
  fi
}
