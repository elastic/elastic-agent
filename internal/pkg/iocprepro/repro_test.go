// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package iocprepro

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
// four MkdirAll calls and two small WriteFile calls per fake install.
func createFakeAgentInstall(t *testing.T, topDir, version, hash string) string {
	t.Helper()

	versionedHome := filepath.Join("data", fmt.Sprintf("elastic-agent-%s-%s", version, hash))
	absHome := filepath.Join(topDir, versionedHome)

	for _, sub := range []string{"", "components", "logs", "run"} {
		require.NoError(t, os.MkdirAll(filepath.Join(absHome, sub), 0o750))
	}

	bin := filepath.Join(absHome, "elastic-agent.exe")
	require.NoError(t, os.WriteFile(bin, []byte(fmt.Sprintf("Placeholder for agent %s", version)), 0o750))
	logFile := filepath.Join(absHome, "logs", "fakelog.ndjson")
	require.NoError(t, os.WriteFile(logFile, []byte(fmt.Sprintf("Sample logs for agent %s", version)), 0o750))

	return versionedHome
}

// createLink mirrors createLink in rollback_test.go: a single os.Symlink call,
// with a regular-file fallback if symlink privilege is unavailable.
func createLink(t *testing.T, topDir, target string) {
	t.Helper()
	link := filepath.Join(topDir, "elastic-agent.exe")
	abs := filepath.Join(topDir, target, "elastic-agent.exe")
	_ = os.Remove(link)
	if err := os.Symlink(abs, link); err != nil {
		require.NoError(t, os.WriteFile(link, []byte("fallback"), 0o750))
	}
}

// createUpdateMarker mirrors createUpdateMarker + LoadMarker in rollback_test.go:
// marshal a struct, write the file, read it back, unmarshal, then Logf("%+v").
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
	require.NoError(t, err)

	markerDir := filepath.Join(topDir, "data")
	require.NoError(t, os.MkdirAll(markerDir, 0o750))
	markerPath := filepath.Join(markerDir, ".update-marker.yml")
	require.NoError(t, os.WriteFile(markerPath, b, 0o600))

	raw, err := os.ReadFile(markerPath)
	require.NoError(t, err)
	var loaded updateMarker
	require.NoError(t, json.Unmarshal(raw, &loaded))
	require.NotNil(t, &loaded)
	t.Logf("Loaded update marker %+v", &loaded)
}

// cleanupBurst mirrors the filesystem half of rollback.go's cleanup(): open the
// data directory, read its entries, remove the symlink, then recursively delete
// each fake install. This is the read+delete IOCP burst that runs immediately
// after the create burst in the real TestCleanup and was missing from the
// first version of this repro.
func cleanupBurst(t *testing.T, topDir string) {
	t.Helper()

	dataDirPath := filepath.Join(topDir, "data")
	dataDir, err := os.Open(dataDirPath)
	require.NoError(t, err)
	subdirs, err := dataDir.Readdirnames(0)
	require.NoError(t, err)
	require.NoError(t, dataDir.Close())

	_ = os.Remove(filepath.Join(topDir, "elastic-agent.exe"))

	for _, sub := range subdirs {
		require.NoError(t, os.RemoveAll(filepath.Join(dataDirPath, sub)))
	}
}

// oneCleanupCycle runs the full create -> marker -> cleanup sequence of a
// single TestCleanup subtest against a fresh temp directory.
func oneCleanupCycle(t *testing.T) {
	t.Helper()
	topDir := t.TempDir()
	oldHome := createFakeAgentInstall(t, topDir, "1.2.3-SNAPSHOT", "abcdef")
	newHome := createFakeAgentInstall(t, topDir, "4.5.6-SNAPSHOT", "ghijkl")
	createLink(t, topDir, newHome)
	createUpdateMarker(t, topDir, oldHome, newHome)
	cleanupBurst(t, topDir)
}

// startBackgroundChurn spawns goroutines that, without ever touching the
// *testing.T (so require/FailNow stays on the test goroutine where it must),
// reproduce the two background conditions the real upgrade.test.exe has but a
// tiny standalone binary lacks:
//
//  1. Heap churn. The real binary links a large import surface and carries a
//     multi-MB live heap, so under GOGC=1 it runs near-continuous large GC
//     cycles. iocprepro's binary is tiny, so GOGC=1 alone barely exercises the
//     GC. The churn goroutines retain a ring of live allocations while
//     producing constant garbage, restoring comparable GC frequency and
//     stack-scan pressure - which is what widens the IOCP-vs-shrinkstack race.
//
//  2. Concurrent IOCP traffic. Extra goroutines run their own create/delete
//     filesystem bursts so the Windows IO completion port is busy while the
//     test goroutine is mid-cycle. Errors are ignored here on purpose: these
//     are load generators, not assertions.
//
// Returns a stop func that signals and waits for all background goroutines.
func startBackgroundChurn(rootDir string) func() {
	stop := make(chan struct{})
	var wg sync.WaitGroup

	nproc := runtime.GOMAXPROCS(0)

	// Heap churn.
	for i := 0; i < nproc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			const ring = 4096
			live := make([][]byte, ring)
			j := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				live[j%ring] = make([]byte, 16+(j&255))
				j++
			}
		}()
	}

	// Concurrent IOCP traffic (no *testing.T access; errors ignored).
	for i := 0; i < nproc; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			base := filepath.Join(rootDir, fmt.Sprintf("churn-%d", id))
			j := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				dir := filepath.Join(base, fmt.Sprintf("i%d", j))
				for _, sub := range []string{"components", "logs", "run"} {
					_ = os.MkdirAll(filepath.Join(dir, sub), 0o750)
				}
				_ = os.WriteFile(filepath.Join(dir, "elastic-agent.exe"), []byte("placeholder"), 0o750)
				_ = os.WriteFile(filepath.Join(dir, "logs", "fakelog.ndjson"), []byte("sample"), 0o750)
				_ = os.RemoveAll(dir)
				j++
			}
		}(i)
	}

	return func() {
		close(stop)
		wg.Wait()
	}
}

// TestSetupBurst is the minimal repro. The test goroutine runs the full
// TestCleanup create->marker->cleanup cycle sequentially (exactly as the real
// subtests do, so require/FailNow stays correctly on the test goroutine),
// while background goroutines drive GC frequency and IOCP traffic up to what
// the real (much larger) upgrade test binary sees under GOGC=1.
//
// Run on Windows under the same env the instrumented CI step uses:
//
//	GOGC=1 GOTRACEBACK=crash
//	GODEBUG=clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1
//	GOEXPERIMENT=cgocheck2
//	go test -race -run TestSetupBurst ./internal/pkg/iocprepro/
func TestSetupBurst(t *testing.T) {
	stopChurn := startBackgroundChurn(t.TempDir())
	defer stopChurn()

	const iters = 3000
	for i := 0; i < iters; i++ {
		oneCleanupCycle(t)
	}
}
