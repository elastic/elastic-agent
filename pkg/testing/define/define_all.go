// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !define && !local && !kubernetes

package define

import (
	"fmt"
	"testing"
)

func defineAction(t *testing.T, req Requirements) *Info {
	return runOrSkip(t, req, false, false)
}

func dryRun(t *testing.T, req Requirements) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		t.Logf("test %s has invalid requirements: %s", t.Name(), err)
		t.FailNow()
		return nil
	}
	// skip the test as we are in dry run
	t.Skip(fmt.Sprintf("Skipped because dry-run mode has been specified."))
	return nil
}
