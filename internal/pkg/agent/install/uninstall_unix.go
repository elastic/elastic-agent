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
// On Windows when running in unprivileged mode the internal way that golang uses DuplicateHandle to perform the kill
// only works when the process is a child of this process.
func killNoneChildProcess(proc *os.Process) error {
	return proc.Kill()
}
