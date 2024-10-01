#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/retry.sh

function ess_up() {
  install_terraform
  echo "~~~ Staring ESS Stack"  
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  local STACK_VERSION=$1
  local ESS_REGION=${2:-"gcp-us-west2"}
    
  if [ -z "$STACK_VERSION" ]; then
    echo "Error: Specify stack version: ess_up [stack_version]" >&2
    return 1
  fi

  export EC_API_KEY=$(retry 5 vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod)
  
  if [[ -z "${EC_API_KEY}" ]]; then
    echo "Error: Failed to get EC API key from vault" >&2
    exit 1
  fi

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
  popd
}

function ess_down() {
  install_terraform
  echo "~~~ Tearing down the ESS Stack"  
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/ess/"
  if [ -z "${EC_API_KEY:-}" ]; then
    export EC_API_KEY=$(retry 5 vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod)    
  fi
  
  pushd "${TF_DIR}"
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

# remove when use custom images
install_terraform() {
  if command -v terraform &> /dev/null; then    
    return 0
  fi
  TERRAFORM_VERSION="1.9.1"
  echo "~~~ Installing Terraform ${TERRAFORM_VERSION}"
  DOWNLOAD_URL="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
  curl -o terraform_${TERRAFORM_VERSION}_linux_amd64.zip $DOWNLOAD_URL
  unzip -o terraform_${TERRAFORM_VERSION}_linux_amd64.zip
  sudo mv terraform /usr/local/bin/
  rm terraform_${TERRAFORM_VERSION}_linux_amd64.zip
  echo "Terraform version $(terraform -v) installed successfully."
}
