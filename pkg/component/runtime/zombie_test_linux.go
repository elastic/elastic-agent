// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package runtime

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/core/process"
)

// assertProcessReaped verifies the process with the given PID is not a zombie.
// On Linux we check /proc/<pid>/stat for the 'Z' (zombie) state via process.IsZombie.
func assertProcessReaped(t *testing.T, pid int) {
	t.Helper()
	if process.IsZombie(pid) {
		t.Errorf("process %d is a zombie (state=Z in /proc/%d/stat)", pid, pid)
	} else {
		t.Logf("process %d is not a zombie", pid)
	}
}
