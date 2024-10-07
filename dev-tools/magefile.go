// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build mage
// +build mage

package main

import (
	"context"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"

	// mage:import
	_ "github.com/elastic/elastic-agent/dev-tools/mage/target/common"
	// mage:import
	"github.com/elastic/elastic-agent/dev-tools/mage/target/test"
)

func init() {
	test.RegisterDeps(GoUnitTest)
}

// GoUnitTest executes the Go unit tests.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
func GoUnitTest(ctx context.Context) {
	devtools.GoTest(ctx, devtools.DefaultGoTestUnitArgs())
}
