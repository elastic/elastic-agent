// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package cmd

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setupParentProcessSignals() error {
	// Perform prctl(PR_SET_PDEATHSIG, 0) to clear the parent death signal
	err := unix.Prctl(unix.PR_SET_PDEATHSIG, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("clearing parent death signal: %w", err)
	}

	return nil
}
