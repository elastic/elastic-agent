// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package notests

import "fmt"

// IntegTest executes integration tests (it uses Docker to run the tests).
func IntegTest() {
	GoIntegTest()
}

// GoIntegTest method informs that no integration tests will be executed.
func GoIntegTest() {
	fmt.Println(">> integTest: Complete (no tests require the integ test environment)")
}
