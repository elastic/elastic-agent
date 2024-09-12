// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package integtest

import (
	"context"

	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/dev-tools/mage/target/test"
)

func init() {
	test.RegisterDeps(IntegTest)
}

var (
	goTestDeps         []interface{}
	whitelistedEnvVars []string
)

// RegisterGoTestDeps registers dependencies of the GoIntegTest target.
func RegisterGoTestDeps(deps ...interface{}) {
	goTestDeps = append(goTestDeps, deps...)
}

// WhitelistEnvVar whitelists an environment variable to enabled it to be
// passed into the clean integration test environment (Docker).
func WhitelistEnvVar(key ...string) {
	whitelistedEnvVars = append(whitelistedEnvVars, key...)
}

// IntegTest executes integration tests (it uses Docker to run the tests).
func IntegTest() {
	mg.SerialDeps(GoIntegTest)
}

// GoIntegTest executes the Go integration tests.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
func GoIntegTest(ctx context.Context) error {
	if !devtools.IsInIntegTestEnv() {
		mg.SerialDeps(goTestDeps...)
	}
	runner, err := devtools.NewDockerIntegrationRunner(whitelistedEnvVars...)
	if err != nil {
		return err
	}
	return runner.Test("goIntegTest", func() error {
		return devtools.GoTest(ctx, devtools.DefaultGoTestIntegrationArgs())
	})
}
