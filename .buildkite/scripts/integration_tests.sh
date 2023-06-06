#!/usr/bin/env bash
set -exuo pipefail

export WORKSPACE=`pwd`

vault kv get -format=json -field=data kv/ci-shared/observability-ingest/cloud/gcp > ./gcp.json
export GOOGLE_APPLICATION_CREDENTIALS=$(realpath ./gcp.json)
export TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE=$(realpath ./gcp.json)  

if ! command -v go &>/dev/null; then  
  echo "Go is not installed. Installing Go..."
  export GO_VERSION=`cat .go-version`
  curl -O https://dl.google.com/go/go$GO_VERSION.linux-amd64.tar.gz
  sudo tar -xf go$GO_VERSION.linux-amd64.tar.gz -C /usr/local
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  source ~/.bashrc
  mkdir $HOME/go
  mkdir $HOME/go/bin
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin  
  echo "Go has been installed."
else
  echo "Go is already installed."
fi

# Installing mage
make mage

# 
# PACKAGE
# 

DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64 PACKAGES=tar.gz mage -v package

#ESS
vault kv get -field api_key kv/ci-shared/observability-ingest/elastic-agent-ess-qa > ./apiKey
export TEST_INTEG_AUTH_ESS_APIKEY_FILE=$(realpath ./apiKey)

# Run integration tests
AGENT_VERSION=8.9.0-SNAPSHOT mage integration:test

# HTML report
go install github.com/alexec/junit2html@latest
junit2html < build/TEST-go-integration.xml > build/TEST-report.html

# A HORRIBLE hack to detect test failures
if grep "<failure" build/TEST-go-integration.xml; then  
  echo "Tests failed."
  exit 1
fi
