#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

# Override the agent package version using a string with format <major>.<minor>.<patch>
# There is a time when the snapshot is not built yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
OVERRIDE_AGENT_PACKAGE_VERSION="$(cat .package-version)"
OVERRIDE_TEST_AGENT_VERSION=${OVERRIDE_AGENT_PACKAGE_VERSION}"-SNAPSHOT"

echo "~~~ Installing Go"
sudo su -

echo "~~~ Installing Go with asdf"
export ASDF_GOLANG_VERSION="1.22.5"
source /opt/buildkite-agent/.asdf/asdf.sh
asdf plugin add golang
asdf install golang $ASDF_GOLANG_VERSION
asdf reshim golang
export GOROOT="$(asdf where golang)/go/"
export GOPATH=$(go env GOPATH)
export PATH="$GOPATH/bin:$PATH"

echo "~~~ Installing Mage"
install_mage

# TODO fix
echo "~~~ Building test binaries"
mage build:testBinaries

ess_up $OVERRIDE_TEST_AGENT_VERSION || echo "Failed to start ESS stack" >&2
trap 'ess_down' EXIT

# Run integration tests
echo "~~~ Running integration tests"
# AGENT_VERSION="${OVERRIDE_TEST_AGENT_VERSION}"
AGENT_VERSION="8.16.0-SNAPSHOT" RUN_SUDO=true SNAPSHOT=true TEST_DEFINE_PREFIX=sudo_linux go test -tags integration github.com/elastic/elastic-agent/testing/integration
