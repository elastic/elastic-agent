// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgradetest

import "os"

// killNoneChildProcess provides a way of killing a process that is not started as a child of this process.
//
// On Unix systems it just calls the native golang kill.
func killNoneChildProcess(proc *os.Process) error {
	return proc.Kill()
}
