// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package runtime

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// assertProcessReaped verifies the process with the given PID is not a zombie.
// On Linux we check /proc/<pid>/stat for the 'Z' (zombie) state.
func assertProcessReaped(t *testing.T, pid int) {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		// Process entry doesn't exist — it has been fully reaped.
		t.Logf("process %d fully reaped (no /proc entry)", pid)
		return
	}

	s := string(data)
	idx := strings.LastIndex(s, ") ")
	if idx == -1 || idx+2 >= len(s) {
		t.Logf("process %d: could not parse /proc/stat, assuming reaped", pid)
		return
	}
	state := s[idx+2]
	if state == 'Z' {
		t.Errorf("process %d is a zombie (state=Z in /proc/%d/stat)", pid, pid)
	} else {
		t.Logf("process %d state: %c (not a zombie)", pid, state)
	}
}
