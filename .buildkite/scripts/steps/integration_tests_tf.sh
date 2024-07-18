#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

install_go
install_mage

sudo usermod -aG adm buildkite-agent
newgrp adm

# source .buildkite/scripts/steps/ess.sh

# Override the agent package version using a string with format <major>.<minor>.<patch>
# There is a time when the snapshot is not built yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
# OVERRIDE_AGENT_PACKAGE_VERSION="$(cat .package-version)"
# OVERRIDE_TEST_AGENT_VERSION=${OVERRIDE_AGENT_PACKAGE_VERSION}"-SNAPSHOT"

mage build:testBinaries

ess_up $OVERRIDE_TEST_AGENT_VERSION || echo "Failed to start ESS stack" >&2
trap 'ess_down' EXIT

# Run integration tests
echo "~~~ Running integration tests"
# AGENT_VERSION="${OVERRIDE_TEST_AGENT_VERSION}"
AGENT_VERSION="8.16.0-SNAPSHOT" SNAPSHOT=true TEST_DEFINE_PREFIX=non_sudo_linux go test -tags integration github.com/elastic/elastic-agent/testing/integration
