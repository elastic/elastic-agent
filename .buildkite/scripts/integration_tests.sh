#!/usr/bin/env bash
set -exuo pipefail

#ESS
vault kv get -field api_key kv/ci-shared/observability-ingest/elastic-agent-ess-qa > ./apiKey
export TEST_INTEG_AUTH_ESS_APIKEY_FILE=$(realpath ./apiKey)

# Run integration tests
mage integration:auth
AGENT_VERSION=8.9.0-SNAPSHOT mage integration:test

# HTML report
go install github.com/alexec/junit2html@latest
junit2html < build/TEST-go-integration.xml > build/TEST-report.html

# TODO: A HORRIBLE hack to detect test failures
if grep "<failure" build/TEST-go-integration.xml; then  
  echo "Tests failed."
  exit 1
fi
