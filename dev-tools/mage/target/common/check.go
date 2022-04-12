// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import (
	"fmt"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

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

// CheckNoChanges runs the linters and checks for changes in git
func CheckNoChanges() error {
	fmt.Println(">> fmt - go run")
	err := sh.RunV("go", "mod", "tidy", "-v")
	if err != nil {
		return fmt.Errorf("failed running go mod tidy, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - git diff")
	err = sh.RunV("git", "diff")
	if err != nil {
		return fmt.Errorf("failed running git diff, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - git update-index")
	err = sh.RunV("git", "update-index", "--refresh")
	if err != nil {
		return fmt.Errorf("failed running git update-index --refresh, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - git diff-index")
	err = sh.RunV("git", "diff-index", "--exit-code", "HEAD", " --")
	if err != nil {
		return fmt.Errorf("failed running go mod tidy, please fix the issues reported: %w", err)
	}
	return nil
}
