#!/usr/bin/env bash
set -exuo pipefail

# PACKAGE
DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64 PACKAGES=tar.gz mage -v package

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
