// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows && !linux

package runtime

import (
	"os"
	"syscall"
	"testing"
)

// assertProcessReaped verifies the process with the given PID has been reaped.
// On non-Linux Unix systems we check that Signal(0) fails, indicating the
// process no longer exists.
func assertProcessReaped(t *testing.T, pid int) {
	t.Helper()
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Logf("process %d not found, fully reaped", pid)
		return
	}
	err = proc.Signal(syscall.Signal(0))
	if err != nil {
		t.Logf("process %d not signalable: %v (reaped)", pid, err)
	} else {
		t.Errorf("process %d is still signalable (may be zombie or still running)", pid)
	}
}
