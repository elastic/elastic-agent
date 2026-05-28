// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package iocprepro

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// updateMarker mirrors the field layout of elastic-agent's UpdateMarker so
// that JSON marshaling produces a payload of similar size and pointer-density
// to what setupAgents writes in the failing TestCleanup subtests.
type updateMarker struct {
	Version           string         `json:"version"`
	Hash              string         `json:"hash"`
	VersionedHome     string         `json:"versioned_home"`
	UpdatedOn         time.Time      `json:"updated_on"`
	PrevVersion       string         `json:"prev_version"`
	PrevHash          string         `json:"prev_hash"`
	PrevVersionedHome string         `json:"prev_versioned_home"`
	Acked             bool           `json:"acked"`
	Action            *markerAction  `json:"action"`
	Details           map[string]any `json:"details"`
}

type markerAction struct {
	ActionID   string `json:"action_id"`
	ActionType string `json:"action_type"`
}

// createFakeAgentInstall mirrors the operations in
// internal/pkg/agent/application/upgrade/rollback_test.go's createFakeAgentInstall:
// four MkdirAll calls and two small WriteFile calls per fake install. The
// data values are intentionally similar in length and shape to the real ones.
func createFakeAgentInstall(t *testing.T, topDir, version, hash string) string {
	t.Helper()

	versionedHome := filepath.Join("data", fmt.Sprintf("elastic-agent-%s-%s", version, hash))
	absHome := filepath.Join(topDir, versionedHome)

	for _, sub := range []string{"", "components", "logs", "run"} {
		if err := os.MkdirAll(filepath.Join(absHome, sub), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}

	bin := filepath.Join(absHome, "elastic-agent.exe")
	if err := os.WriteFile(bin, []byte(fmt.Sprintf("Placeholder for agent %s", version)), 0o750); err != nil {
		t.Fatalf("WriteFile bin: %v", err)
	}
	logFile := filepath.Join(absHome, "logs", "fakelog.ndjson")
	if err := os.WriteFile(logFile, []byte(fmt.Sprintf("Sample logs for agent %s", version)), 0o750); err != nil {
		t.Fatalf("WriteFile log: %v", err)
	}

	return versionedHome
}

// createLink mirrors createLink in rollback_test.go: a single os.Symlink call.
func createLink(t *testing.T, topDir, target string) {
	t.Helper()
	link := filepath.Join(topDir, "elastic-agent.exe")
	abs := filepath.Join(topDir, target, "elastic-agent.exe")
	// Remove any existing link from a prior iteration; testify's setup is
	// per-subtest so we get a fresh topDir each time, but be defensive in
	// case the loop body changes later.
	_ = os.Remove(link)
	if err := os.Symlink(abs, link); err != nil {
		// Symlink creation requires SeCreateSymbolicLinkPrivilege on Windows.
		// If we can't create one, fall back to a regular file so the rest of
		// the pattern still exercises IOCP - the crash has been observed
		// even on runs where symlink creation was rate-limited.
		if err := os.WriteFile(link, []byte("fallback"), 0o750); err != nil {
			t.Fatalf("symlink (and writefile fallback): %v", err)
		}
	}
}

// createUpdateMarker mirrors createUpdateMarker in rollback_test.go: build a
// struct, marshal to JSON, write the file, read it back, then log it via
// t.Logf("%+v", ...). The final t.Logf exercises the fmt-Stringer chain
// where build 40495's secondary nil-deref dump fired.
func createUpdateMarker(t *testing.T, topDir, oldHome, newHome string) {
	t.Helper()

	m := updateMarker{
		Version:           "4.5.6-SNAPSHOT",
		Hash:              "ghijkl",
		VersionedHome:     newHome,
		UpdatedOn:         time.Now().UTC(),
		PrevVersion:       "1.2.3-SNAPSHOT",
		PrevHash:          "abcdef",
		PrevVersionedHome: oldHome,
		Acked:             false,
		Action: &markerAction{
			ActionID:   "fake-action-id-0123456789abcdef",
			ActionType: "UPGRADE",
		},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	markerDir := filepath.Join(topDir, "data")
	if err := os.MkdirAll(markerDir, 0o750); err != nil {
		t.Fatalf("MkdirAll marker: %v", err)
	}
	markerPath := filepath.Join(markerDir, ".update-marker.yml")
	if err := os.WriteFile(markerPath, b, 0o600); err != nil {
		t.Fatalf("WriteFile marker: %v", err)
	}

	raw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("ReadFile marker: %v", err)
	}
	var loaded updateMarker
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	t.Logf("Loaded update marker %+v", &loaded)
}

// TestSetupBurst is the minimal repro. Each iteration mimics one subtest of
// rollback_test.go's TestCleanup:
//
//   - createFakeAgentInstall for the "from" version (4 mkdirs + 2 writes)
//   - createFakeAgentInstall for the "to" version (4 mkdirs + 2 writes)
//   - createLink (1 symlink)
//   - createUpdateMarker (marshal + write + read + log)
//
// Build 40511 observed the crash within ~3 ms of `=== RUN` for a subtest, so
// the bug fires deep inside the burst on a normal-speed system. The outer
// loop simply amortizes the race window; lowering iters is fine for
// experimenting with reducing the cycle further.
func TestSetupBurst(t *testing.T) {
	const iters = 500

	for i := 0; i < iters; i++ {
		topDir := t.TempDir()

		oldHome := createFakeAgentInstall(t, topDir, "1.2.3-SNAPSHOT", "abcdef")
		newHome := createFakeAgentInstall(t, topDir, "4.5.6-SNAPSHOT", "ghijkl")
		createLink(t, topDir, newHome)
		createUpdateMarker(t, topDir, oldHome, newHome)
	}
}
