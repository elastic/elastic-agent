package main

import (
	devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"
	"testing"


)

// Test started when the test binary is started. Only calls main.
func TestPackage(t *testing.T) {
	devtools.Snapshot = true
	devtools.PLATFORMS = "linux/arm64"
	devtools.ExternalBuild = true
	//Package()
}
