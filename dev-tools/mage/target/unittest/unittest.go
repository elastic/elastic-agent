// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package unittest

import (
	"context"

	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/dev-tools/mage/target/test"
)

func init() {
	test.RegisterDeps(UnitTest)
}

var (
	goTestDeps []interface{}
)

// RegisterGoTestDeps registers dependencies of the GoUnitTest target.
func RegisterGoTestDeps(deps ...interface{}) {
	goTestDeps = append(goTestDeps, deps...)
}

// UnitTest executes the unit tests (Go).
func UnitTest() {
	mg.SerialDeps(GoUnitTest)
}

// GoUnitTest executes the Go unit tests.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
func GoUnitTest(ctx context.Context) error {
	mg.SerialCtxDeps(ctx, goTestDeps...)
	return devtools.GoTest(ctx, devtools.DefaultGoTestUnitArgs())
}
