// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Command lintplan prints the lint tag-set plan as JSON for CI. It is a
// lightweight entrypoint so the plan can be computed cheaply, without the
// heavier setup the mage entrypoint needs.
package main

import (
	"fmt"
	"os"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

func main() {
	if err := devtools.LintPlan(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
