// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// stripDiagnostics are the options of the cleanups that strip the homes kept for diagnostics.
var stripDiagnostics = cleanupOpts{stripDiagnostics: true}

// addTTL marks the install in versionedHome with a TTL marker of the given kind.
func addTTL(t *testing.T, registry *ttl.TTLMarkerRegistry, versionedHome string, kind ttl.Kind, validFor time.Duration) {
	t.Helper()
	require.NoError(t, registry.Add(versionedHome, ttl.TTLMarker{Version: "1.0.0", Hash: "abcdef", ValidUntil: time.Now().Add(validFor), Kind: kind}))
}

const diagnosticsLogName = "elastic-agent-watcher.ndjson"

func TestCleanAvailableRollbacks_DiagnosticsHomes(t *testing.T) {
	// the homes of the same setup are checked after a cleanup with and without the strip
	type homes struct{ current, diagnostics, rollback, unknownKind, expiredDiagnostics string }
	setup := func(t *testing.T) (topDir string, h homes, registry *ttl.TTLMarkerRegistry) {
		t.Helper()
		log, _ := loggertest.New(t.Name())
		topDir = t.TempDir()
		h = homes{
			current:            createFakeAgentInstall(t, topDir, "9.5.3", "0e70ce", true),
			diagnostics:        createFakeAgentInstall(t, topDir, "9.5.4", "b18dae", true),
			rollback:           createFakeAgentInstall(t, topDir, "9.5.2", "c0ffee", true),
			unknownKind:        createFakeAgentInstall(t, topDir, "9.5.5", "d00d00", true),
			expiredDiagnostics: createFakeAgentInstall(t, topDir, "9.5.1", "badbad", true),
		}
		require.NoError(t, os.WriteFile(filepath.Join(topDir, h.diagnostics, "logs", diagnosticsLogName), []byte("Error detected, proceeding to rollback"), 0o640))
		registry = ttl.NewTTLMarkerRegistry(log, topDir)
		addTTL(t, registry, h.diagnostics, ttl.KindDiagnostics, time.Hour)
		addTTL(t, registry, h.rollback, ttl.KindRollback, time.Hour)
		addTTL(t, registry, h.unknownKind, "from-the-future", time.Hour)
		addTTL(t, registry, h.expiredDiagnostics, ttl.KindDiagnostics, -time.Hour)
		return topDir, h, registry
	}
	isFull := func(topDir, home string) bool {
		_, err := os.Stat(filepath.Join(topDir, home, "components"))
		return err == nil
	}

	t.Run("without the strip option the diagnostics home is kept whole", func(t *testing.T) {
		topDir, h, registry := setup(t)
		log, _ := loggertest.New(t.Name())

		_, err := CleanAvailableRollbacks(log, registry, topDir, h.current, time.Now(), CleanupExpiredRollbacks)

		require.NoError(t, err)
		assert.True(t, isFull(topDir, h.diagnostics), "a diagnostics home is not stripped when the agent starts")
	})

	t.Run("with the strip option the diagnostics home is stripped to its logs and marker", func(t *testing.T) {
		topDir, h, registry := setup(t)
		log, _ := loggertest.New(t.Name())

		_, err := cleanAvailableRollbacksWithOpts(log, registry, topDir, h.current, time.Now(), CleanupExpiredRollbacks, stripDiagnostics)

		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(topDir, h.diagnostics, "logs", diagnosticsLogName), "the logs must survive the strip")
		assert.FileExists(t, filepath.Join(topDir, h.diagnostics, ttl.MarkerFileName))
		assert.True(t, hasOnlyLogs(log, filepath.Join(topDir, h.diagnostics)), "the diagnostics home must be stripped down to its logs")
		assert.True(t, isFull(topDir, h.rollback), "a rollback target must not be stripped")
		assert.True(t, isFull(topDir, h.unknownKind), "an install kept for an unknown reason must not be stripped")
		assert.True(t, isFull(topDir, h.current), "the current install must not be stripped")
		assert.NoDirExists(t, filepath.Join(topDir, h.expiredDiagnostics), "an expired diagnostics home is removed whole")
	})

	t.Run("the strip is repeatable", func(t *testing.T) {
		topDir, h, registry := setup(t)
		log, _ := loggertest.New(t.Name())

		for range 2 {
			_, err := cleanAvailableRollbacksWithOpts(log, registry, topDir, h.current, time.Now(), CleanupExpiredRollbacks, stripDiagnostics)
			require.NoError(t, err)
		}

		assert.True(t, hasOnlyLogs(log, filepath.Join(topDir, h.diagnostics)))
	})

	t.Run("a home the active upgrade refers to is not stripped", func(t *testing.T) {
		topDir, h, registry := setup(t)
		log, _ := loggertest.New(t.Name())
		// an upgrade, still in progress, that unpacks into the home that was kept for diagnostics
		require.NoError(t, SaveMarker(paths.DataFrom(topDir), &UpdateMarker{VersionedHome: h.diagnostics, PrevVersionedHome: h.current}, false))

		_, err := cleanAvailableRollbacksWithOpts(log, registry, topDir, h.current, time.Now(), CleanupExpiredRollbacks, stripDiagnostics)

		require.NoError(t, err)
		assert.True(t, isFull(topDir, h.diagnostics))
	})

	t.Run("a diagnostics marker on the home of the current install does not strip it", func(t *testing.T) {
		topDir, h, registry := setup(t)
		log, _ := loggertest.New(t.Name())
		addTTL(t, registry, h.current, ttl.KindDiagnostics, time.Hour)

		_, err := cleanAvailableRollbacksWithOpts(log, registry, topDir, h.current, time.Now(), CleanupExpiredRollbacks, stripDiagnostics)

		require.NoError(t, err)
		assert.True(t, isFull(topDir, h.current))
	})
}

// A strip that cannot finish is not critical: it is a warning and the next periodic cleanup retries it.
func TestPerformScheduledCleanup_DiagnosticsStrip(t *testing.T) {
	now := time.Now()
	const minInterval = 10 * time.Minute

	t.Run("a stripped home is scheduled for its expiry", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		topDir := t.TempDir()
		current := createFakeAgentInstall(t, topDir, "9.5.3", "0e70ce", true)
		diagnostics := createFakeAgentInstall(t, topDir, "9.5.4", "b18dae", true)
		registry := ttl.NewTTLMarkerRegistry(log, topDir)
		addTTL(t, registry, diagnostics, ttl.KindDiagnostics, 30*24*time.Hour)

		next := performScheduledCleanup(log, topDir, current, registry, now, minInterval)

		assert.True(t, hasOnlyLogs(log, filepath.Join(topDir, diagnostics)))
		assert.WithinDuration(t, now.Add(30*24*time.Hour), next, time.Minute)
	})

	t.Run("a strip that cannot finish is a warning and is retried after the interval", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs something that cannot be removed, which permissions do not give on Windows or as root")
		}
		log, logs := loggertest.New(t.Name())
		topDir := t.TempDir()
		current := createFakeAgentInstall(t, topDir, "9.5.3", "0e70ce", true)
		diagnostics := createFakeAgentInstall(t, topDir, "9.5.4", "b18dae", true)
		// the directory cannot be emptied, so the strip cannot remove components
		locked := filepath.Join(topDir, diagnostics, "components", "locked")
		require.NoError(t, os.MkdirAll(locked, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(locked, "file"), []byte("x"), 0o640))
		require.NoError(t, os.Chmod(locked, 0o500))
		t.Cleanup(func() { _ = os.Chmod(locked, 0o750) })
		registry := ttl.NewTTLMarkerRegistry(log, topDir)
		addTTL(t, registry, diagnostics, ttl.KindDiagnostics, 30*24*time.Hour)

		_, err := cleanAvailableRollbacksWithOpts(log, registry, topDir, current, now, CleanupExpiredRollbacks, stripDiagnostics)
		require.Error(t, err)
		assert.True(t, isOnly(err, errStripIncomplete), "only an incomplete strip is reported")

		next := performScheduledCleanup(log, topDir, current, registry, now, minInterval)

		assert.Equal(t, now.Add(minInterval), next, "the strip is retried after the interval")
		assert.NotEmpty(t, logs.FilterMessageSnippet("could not strip every retained diagnostics home").All())
		assert.Zero(t, logs.FilterLevelExact(zapcore.ErrorLevel).Len(), "an incomplete strip is not an error")
	})
}

func TestIsOnly(t *testing.T) {
	other := errors.New("other")

	assert.False(t, isOnly(nil, errStripIncomplete))
	assert.False(t, isOnly(other, errStripIncomplete))
	assert.True(t, isOnly(errStripIncomplete, errStripIncomplete))
	assert.True(t, isOnly(errors.Join(errStripIncomplete, errStripIncomplete), errStripIncomplete))
	assert.False(t, isOnly(errors.Join(errStripIncomplete, other), errStripIncomplete), "another error is not only the target")
	assert.True(t, isDegradedOnly(errCleanupDegraded))
	assert.False(t, isDegradedOnly(errors.Join(errCleanupDegraded, other)))
}
