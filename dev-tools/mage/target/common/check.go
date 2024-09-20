// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

var checkDeps []interface{}

// RegisterCheckDeps registers dependencies of the Check target.
func RegisterCheckDeps(deps ...interface{}) {
	checkDeps = append(checkDeps, deps...)
}

// Check formats code, updates generated content, check for common errors, and
// checks for any modified files.
func Check() {
	deps := make([]interface{}, 0, len(checkDeps)+2)
	deps = append(deps, devtools.Format)
	deps = append(deps, checkDeps...)
	deps = append(deps, devtools.Check)
	mg.SerialDeps(deps...)
}

// CheckLicenseHeaders checks license headers
func CheckLicenseHeaders() {
	mg.Deps(devtools.CheckLicenseHeaders)
}
