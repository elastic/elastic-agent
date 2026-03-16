// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package process

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// externalProcess is a watch mechanism used in cases where OS requires a process to be a child
// for waiting for process. We need to be able to await any process.
func externalProcess(proc *os.Process) {
	if proc == nil {
		return
	}

	for {
		<-time.After(1 * time.Second)
		if proc.Signal(syscall.Signal(0)) != nil {
			// failed to contact process, return
			return
		}
		// On Linux, Signal(0) succeeds for zombie processes because
		// they still have a PID entry in the process table.
		// Check /proc/<pid>/stat to detect zombie state.
		if isZombie(proc.Pid) {
			return
		}
	}
}

// isZombie checks if the process with the given PID is in zombie state
// by reading /proc/<pid>/stat. The format is:
//
//	<pid> (<comm>) <state> ...
//
// where <state> is a single character. 'Z' indicates zombie state.
// We use LastIndex for ") " to handle process names containing parentheses.
func isZombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		// Can't read proc entry (process may have been fully reaped)
		return false
	}
	s := string(data)
	idx := strings.LastIndex(s, ") ")
	if idx == -1 || idx+2 >= len(s) {
		return false
	}
	return s[idx+2] == 'Z'
}
