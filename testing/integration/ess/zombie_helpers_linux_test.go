// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && linux

package ess

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/elastic/elastic-agent/pkg/core/process"
)

// assertProcessGone verifies that the given PID is no longer running. If the
// process is still alive, the test fails. This is used to confirm the agent
// actively killed the component during shutdown (via waitOrKill/SIGKILL)
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
	if process.IsZombie(pid) {
		state = "zombie"
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

	// Wait4 with WNOHANG reaps the process if this test happens to be the
	// parent (e.g., if the agent re-parented the child to us before dying).
	// Without this, the SIGKILL'd process could remain as a zombie for the
	// duration of the test run. WNOHANG ensures we don't block if we're not
	// the parent. Wait4 returns ECHILD if we are not the parent, which we
	// intentionally ignore.
	syscall.Wait4(pid, nil, syscall.WNOHANG, nil) //nolint:errcheck
}
