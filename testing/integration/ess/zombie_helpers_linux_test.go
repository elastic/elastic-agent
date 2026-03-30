// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && linux

package ess

import (
	"syscall"
	"testing"

	"github.com/elastic/elastic-agent/pkg/core/process"
)

// cleanupProcess forcefully kills a process and reaps it. Called from
// t.Cleanup to ensure the SIGTERM-ignoring component doesn't survive the test.
func cleanupProcess(t *testing.T, pid int) {
	t.Helper()

	// Check if still alive first.
	if process.IsReaped(pid) {
		return
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
