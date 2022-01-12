// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package test

import "github.com/magefile/mage/mg"

var (
	testDeps []interface{}
)

// RegisterDeps registers dependencies of the Test target (register your targets
// that execute tests).
func RegisterDeps(deps ...interface{}) {
	testDeps = append(testDeps, deps...)
}

// Test runs all available tests (unitTest + integTest).
func Test() {
	mg.SerialDeps(testDeps...)
}
