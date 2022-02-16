// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"testing"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

// Test started when the test binary is started. Only calls main.
func TestPackage(t *testing.T) {
	devtools.Snapshot = true
	devtools.PLATFORMS = "linux/arm64"
	devtools.ExternalBuild = true
	//Package()
}
