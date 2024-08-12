#!/usr/bin/env bash

# The script is used to run integration tests with sudo
source /opt/buildkite-agent/hooks/pre-command 
source .buildkite/hooks/pre-command || echo "No pre-command hook found"

echo "~~~ Running integration tests as $WHOAMI"
mkdir /usr/share/elastic-agent
go env
# TODO: Pass the actual version of the agent
# AGENT_VERSION="8.16.0-SNAPSHOT" SNAPSHOT=true TEST_DEFINE_PREFIX=sudo_linux gotestsum --no-color -f standard-verbose --junitfile build/TEST-go-integration.xml --jsonfile build/TEST-go-integration.out.json -- -tags integration github.com/elastic/elastic-agent/testing/integration