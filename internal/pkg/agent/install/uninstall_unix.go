// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package install

import "os"

func isBlockingOnExe(_ error) bool {
	return false
}

func removeBlockingExe(_ error) error {
	return nil
}

func isRetryableError(_ error) bool {
	return false
}

// killNoneChildProcess provides a way of killing a process that is not started as a child of this process.
//
// On Unix systems it just calls the native golang kill.
func killNoneChildProcess(proc *os.Process) error {
	return proc.Kill()
}
