// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build mage

package main

import devtools "github.com/elastic/elastic-agent/dev-tools/mage"

// LintPlan prints the build-tag sets to lint as JSON for the CI matrix.
// LINT_PLAN_BASE selects the diff base; unset plans all sets.
//
// Kept in its own file so it doesn't drag magefile.go into a PR's diff, which
// would surface that file's pre-existing lint findings.
func (Check) LintPlan() error {
	return devtools.LintPlan()
}
