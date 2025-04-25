#!/usr/bin/env bash
set -euo pipefail

function serverless_up() {
  echo "~~~ Starting Serverless Observability project"
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/serverless/"

  export EC_API_KEY=$(retry -t 5 -- vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod)

  if [[ -z "${EC_API_KEY}" ]]; then
    echo "Error: Failed to get EC API key from vault" >&2
    exit 1
  fi

  pushd "${TF_DIR}"
  terraform init
  terraform apply -auto-approve

  export ELASTICSEARCH_HOST=$(terraform output -raw es_host)
  export ELASTICSEARCH_USERNAME=$(terraform output -raw es_username)
  export ELASTICSEARCH_PASSWORD=$(terraform output -raw es_password)
  export KIBANA_HOST=$(terraform output -raw kibana_endpoint)
  export KIBANA_USERNAME=$ELASTICSEARCH_USERNAME
  export KIBANA_PASSWORD=$ELASTICSEARCH_PASSWORD
  popd
}

function serverless_down() {
  echo "~~~ Tearing down the Serverless Observability project"
  local WORKSPACE=$(git rev-parse --show-toplevel)
  local TF_DIR="${WORKSPACE}/test_infra/serverless/"
  if [ -z "${EC_API_KEY:-}" ]; then
    export EC_API_KEY=$(retry -t 5 -- vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod)
  fi

  pushd "${TF_DIR}"
  terraform init
  terraform destroy -auto-approve
  popd
}
