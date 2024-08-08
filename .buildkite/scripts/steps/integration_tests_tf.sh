#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh
source .buildkite/scripts/steps/ess.sh


# Override the agent package version using a string with format <major>.<minor>.<patch>
# There is a time when the snapshot is not built yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
OVERRIDE_AGENT_PACKAGE_VERSION="$(cat .package-version)"
OVERRIDE_TEST_AGENT_VERSION=${OVERRIDE_AGENT_PACKAGE_VERSION}"-SNAPSHOT"

echo "~~~ Bulding test binaries"
mage build:testBinaries

ess_up $OVERRIDE_TEST_AGENT_VERSION || echo "Failed to start ESS stack" >&2
trap 'ess_down' EXIT

echo "~~~ Running integration tests"
AGENT_VERSION="8.16.0-SNAPSHOT" SNAPSHOT=true TEST_DEFINE_PREFIX=non_sudo_linux gotestsum --no-color -f standard-verbose --junitfile build/TEST-go-integration.xml --jsonfile build/TEST-go-integration.out.json -- -tags integration github.com/elastic/elastic-agent/testing/integration

#
# GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH" AGENT_VERSION="%s" TEST_DEFINE_PREFIX="%s" TEST_DEFINE_TESTS="%s" (-v) mage test:integration
# Env description:
#  TEST_DEFINE_TESTS="${package}:${test_name}, ${package}:${test_name}, ..." 
#  TEST_DEFINE_PREFIX="non_sudo_linux (random thing)"
# + env: vars from terraform
#
# VVV
#
# ### integration:TestOnRemote
#  
#  env: 
#   GOTEST_FLAGS=...,... - unknown
#
# VVV
# magefile:2424
# params := mage.GoTestArgs{
# 			LogName:         testName,
# 			OutputFile:      fileName + ".out",
# 			JUnitReportFile: fileName + ".xml",
# 			Packages:        []string{packageName},
# 			Tags:            []string{"integration"},
# 			ExtraFlags:      extraFlags,
# 			Env: map[string]string{
# 				"AGENT_VERSION":      version,
# 				"TEST_DEFINE_PREFIX": testPrefix,
# 			},
# 		}
# 		err := devtools.GoTest(ctx, params)
#
# packageName ??? is it the same as batch group?
# extraFlags ??? - taken from env vars and many other places.
#
# VVV
#
# ### gotest.go func GoTest
# See comments in the code
# gotestsumArgs:
# --no-color
# -f standard-quiet
# --junitfile somefile
# --jsonfile somefile
# 
# testArgs:
# -race
# -tags integraion  (comes from Params ^^^)
# covermode - skip from now
# 

