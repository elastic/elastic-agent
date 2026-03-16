// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package main

import "golang.org/x/sys/unix"

// clearPdeathsig clears the parent-death signal so this process survives its
// parent exiting. Used in tests to verify the agent actively kills components
// during shutdown rather than relying on Pdeathsig.
func clearPdeathsig() {
	_ = unix.Prctl(unix.PR_SET_PDEATHSIG, 0, 0, 0, 0)
}
