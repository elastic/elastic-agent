// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows && !linux

package process

import (
	"os"
	"syscall"
	"time"
)

// externalProcess is a watch mechanism used in cases where OS requires a process to be a child
// for waiting for process. We need to be able to await any process.
func externalProcess(proc *os.Process) {
	if proc == nil {
		return
	}

	ticker := time.NewTicker(externalPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		if proc.Signal(syscall.Signal(0)) != nil {
			// failed to contact process, return
			return
		}
	}
}

// IsReaped returns true if the process with the given PID has fully exited.
// On Unix, os.FindProcess always succeeds (it just wraps the PID without
// checking the process table), so we use Signal(0) for the actual check.
func IsReaped(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil || proc == nil {
		return true // can't find -> treat as reaped
	}
	return proc.Signal(syscall.Signal(0)) != nil
}
