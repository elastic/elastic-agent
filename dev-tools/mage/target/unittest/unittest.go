// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package unittest

import (
	"context"

	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"
	"github.com/elastic/elastic-agent-poc/dev-tools/mage/target/test"
)

func init() {
	test.RegisterDeps(UnitTest)
}

var (
	goTestDeps, pythonTestDeps []interface{}
)

// RegisterGoTestDeps registers dependencies of the GoUnitTest target.
func RegisterGoTestDeps(deps ...interface{}) {
	goTestDeps = append(goTestDeps, deps...)
}

// RegisterPythonTestDeps registers dependencies of the PythonUnitTest target.
func RegisterPythonTestDeps(deps ...interface{}) {
	pythonTestDeps = append(pythonTestDeps, deps...)
}

// UnitTest executes the unit tests (Go and Python).
func UnitTest() {
	mg.SerialDeps(GoUnitTest, PythonUnitTest)
}

// GoUnitTest executes the Go unit tests.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
func GoUnitTest(ctx context.Context) error {
	mg.SerialCtxDeps(ctx, goTestDeps...)
	return devtools.GoTest(ctx, devtools.DefaultGoTestUnitArgs())
}

// PythonUnitTest executes the python system tests.
func PythonUnitTest() error {
	mg.SerialDeps(pythonTestDeps...)
	mg.Deps(devtools.BuildSystemTestBinary)
	return devtools.PythonTest(devtools.DefaultPythonTestUnitArgs())
}
