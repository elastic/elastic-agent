// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && linux

package ess

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// assertProcessGone verifies that the given PID is no longer running. If the
// process is still alive, the test fails. This is used to confirm the agent
// actively killed the component during shutdown (via cleanupProcess/SIGKILL)
// rather than leaving it running.
func assertProcessGone(t *testing.T, pid int) {
	t.Helper()

	// Check if the process is still alive via kill(pid, 0).
	if err := unix.Kill(pid, 0); err != nil {
		t.Logf("process %d is gone (kill returned: %v)", pid, err)
		return
	}

	// Process is still alive — also check if it's a zombie.
	state := "alive"
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		s := string(data)
		idx := strings.LastIndex(s, ") ")
		if idx != -1 && idx+2 < len(s) && s[idx+2] == 'Z' {
			state = "zombie"
		}
	}

	t.Fatalf("process %d is still %s after agent shutdown — agent did not kill the component during shutdown", pid, state)
}

// cleanupProcess forcefully kills a process and reaps it. Called from
// t.Cleanup to ensure the SIGTERM-ignoring component doesn't survive the test.
func cleanupProcess(t *testing.T, pid int) {
	t.Helper()

	// Check if still alive first.
	if err := unix.Kill(pid, 0); err != nil {
		return // already gone
	}

	t.Logf("cleanup: killing leftover component process %d", pid)
	_ = syscall.Kill(pid, syscall.SIGKILL)

	// Reap if we're the parent (unlikely, but handle it).
	syscall.Wait4(pid, nil, syscall.WNOHANG, nil) //nolint:errcheck
}
