// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestEncryptedAgentInfoStore_SavePartialMerge(t *testing.T) {
	initial := map[string]interface{}{
		"agent": map[string]interface{}{
			"id":            "agent-id",
			"headers":       map[string]string{"x": "y"},
			"logging.level": "info",
		},
		"fleet": map[string]interface{}{
			"enabled":        true,
			"access_api_key": "key",
		},
	}
	ctx := setupEncryptedStore(t, initial)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithLogLevelOverride("debug")))

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "agent-id", info.AgentID)
	require.Equal(t, "info", info.LogLevelPolicy)
	require.Equal(t, "debug", info.LogLevelOverride)

	// fleet section must still be present
	got := readEncrypted(t, ctx)
	require.NotNil(t, got["fleet"])
}

func TestEncryptedAgentInfoStore_SaveClearOverride(t *testing.T) {
	initial := map[string]interface{}{
		"agent": map[string]interface{}{
			"id":                     "agent-id",
			"logging.level":          "info",
			"logging.level_override": "warning",
		},
	}
	ctx := setupEncryptedStore(t, initial)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithLogLevelOverride("")))

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "", info.LogLevelOverride, "empty override level should remove the key")
	require.Equal(t, "agent-id", info.AgentID)
	require.Equal(t, "info", info.LogLevelPolicy)
}

func TestEncryptedAgentInfoStore_LoadStandaloneVsManaged(t *testing.T) {
	t.Run("no fleet section is treated as standalone", func(t *testing.T) {
		ctx := setupEncryptedStore(t, map[string]interface{}{
			"agent": map[string]interface{}{"id": "test-id"},
		})

		got, err := NewAgentInfo(ctx, false)
		require.NoError(t, err)
		require.Equal(t, "test-id", got.AgentID)
		require.True(t, got.isStandalone)
	})

	t.Run("fleet.enabled=true is treated as managed", func(t *testing.T) {
		ctx := setupEncryptedStore(t, map[string]interface{}{
			"agent": map[string]interface{}{"id": "test-id"},
			"fleet": map[string]interface{}{"enabled": true},
		})

		got, err := NewAgentInfo(ctx, false)
		require.NoError(t, err)
		require.Equal(t, "test-id", got.AgentID)
		require.False(t, got.isStandalone)
	})
}

func TestEncryptedAgentInfoStore_SavePolicyBatch(t *testing.T) {
	// Initial state has an override that policy save must NOT touch.
	initial := map[string]interface{}{
		"agent": map[string]interface{}{
			"id":                     "agent-id",
			"logging.level_override": "warning",
		},
		"fleet": map[string]interface{}{"enabled": true},
	}
	ctx := setupEncryptedStore(t, initial)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx,
		WithLogLevelPolicy("debug"),
		WithEventLoggingToFiles(true),
		WithEventLoggingToStderr(false),
	))

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "debug", info.LogLevelPolicy)
	// override preserved across the policy save
	require.Equal(t, "warning", info.LogLevelOverride)

	// event_data fields land at agent.logging.event_data.{to_files,to_stderr};
	// drill in via the raw map to verify.
	got := readEncrypted(t, ctx)
	agent := got["agent"].(map[string]interface{})
	logging := agent["logging"].(map[string]interface{})
	eventData := logging["event_data"].(map[string]interface{})
	require.Equal(t, true, eventData["to_files"])
	require.Equal(t, false, eventData["to_stderr"])
	// fleet preserved
	require.NotNil(t, got["fleet"])
}

// setupEncryptedStore prepares a temp encrypted store with the given initial
// contents and returns a context bound to test lifetime.
func setupEncryptedStore(t *testing.T, initial map[string]interface{}) context.Context {
	t.Helper()
	ctx, encPath := setupEmptyStorePaths(t)

	store, err := storage.NewEncryptedDiskStore(ctx, encPath)
	require.NoError(t, err)
	rawYAML, err := yaml.Marshal(initial)
	require.NoError(t, err)
	require.NoError(t, store.Save(bytes.NewReader(rawYAML)))
	return ctx
}

// setupEmptyStorePaths configures paths for an encrypted store but does not
// create the file. Returns the context and the expected file path.
func setupEmptyStorePaths(t *testing.T) (context.Context, string) {
	t.Helper()

	if runtime.GOOS == "darwin" {
		t.Skip("vault requires extra perms on mac")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	tmpPath := t.TempDir()
	paths.SetConfig(tmpPath)

	vaultPath := filepath.Join(tmpPath, "vault")
	require.NoError(t, secret.CreateAgentSecret(ctx, vault.WithVaultPath(vaultPath)))

	encPath := filepath.Join(tmpPath, "fleet.enc")
	require.Equal(t, encPath, paths.AgentConfigFile())
	return ctx, encPath
}

func TestEncryptedAgentInfoStore_SaveCreatesFileWhenMissing(t *testing.T) {
	ctx, encPath := setupEmptyStorePaths(t)
	require.NoFileExists(t, encPath)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithID("new-agent")))
	require.FileExists(t, encPath)

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "new-agent", info.AgentID)
}

func TestEncryptedAgentInfoStore_LoadWhenFileMissing(t *testing.T) {
	ctx, encPath := setupEmptyStorePaths(t)
	require.NoFileExists(t, encPath)

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Empty(t, info.AgentID)
	require.True(t, info.isStandalone, "missing file should default to standalone")
}

func TestEncryptedAgentInfoStore_SaveNoOptsIsNoOp(t *testing.T) {
	ctx, encPath := setupEmptyStorePaths(t)
	require.NoFileExists(t, encPath)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx))
	require.NoFileExists(t, encPath, "Save with no options must not create the file")
}

func TestEncryptedAgentInfoStore_ClearLogLevelPolicy(t *testing.T) {
	initial := map[string]interface{}{
		"agent": map[string]interface{}{
			"id":                     "agent-id",
			"logging.level":          "warning",
			"logging.level_override": "debug",
		},
	}
	ctx := setupEncryptedStore(t, initial)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithLogLevelPolicy("")))

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "", info.LogLevelPolicy, "empty policy level should remove the key")
	require.Equal(t, "debug", info.LogLevelOverride, "override should remain untouched")
	require.Equal(t, "agent-id", info.AgentID)
}

func TestEncryptedAgentInfoStore_WithFleetWholesaleReplacement(t *testing.T) {
	initial := map[string]interface{}{
		"agent": map[string]interface{}{"id": "agent-id"},
		"fleet": map[string]interface{}{
			"enabled":        true,
			"access_api_key": "old-key",
			"client": map[string]interface{}{
				"host": "old.host",
			},
		},
	}
	ctx := setupEncryptedStore(t, initial)

	newFleet := map[string]interface{}{
		"enabled":        true,
		"access_api_key": "new-key",
	}
	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithFleet(newFleet)))

	got := readEncrypted(t, ctx)
	require.Equal(t, newFleet, got["fleet"], "fleet section must be replaced wholesale, not merged")
	// agent section preserved
	agent := got["agent"].(map[string]interface{})
	require.Equal(t, "agent-id", agent["id"])
}

func TestEncryptedAgentInfoStore_WithIDRoundTrip(t *testing.T) {
	ctx, _ := setupEmptyStorePaths(t)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithID("first")))
	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "first", info.AgentID)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithID("second")))
	info, err = NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "second", info.AgentID)
}

func TestEncryptedAgentInfoStore_SetNestedOptions(t *testing.T) {
	ctx := setupEncryptedStore(t, map[string]interface{}{
		"agent": map[string]interface{}{"id": "agent-id"},
	})

	headers := map[string]string{"x-test": "yes"}
	httpCfg := map[string]interface{}{"enabled": true, "host": "127.0.0.1"}
	pprofCfg := map[string]interface{}{"enabled": false}

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx,
		WithHeaders(headers),
		WithMonitoringHTTP(httpCfg),
		WithMonitoringPprof(pprofCfg),
	))

	got := readEncrypted(t, ctx)
	agent := got["agent"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"x-test": "yes"}, agent["headers"])
	monitoring := agent["monitoring"].(map[string]interface{})
	require.Equal(t, httpCfg, monitoring["http"])
	require.Equal(t, pprofCfg, monitoring["pprof"])
}

func TestNullAgentInfoStore(t *testing.T) {
	var s NullAgentInfoStore
	ctx := context.Background()

	info, err := s.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Empty(t, info.AgentID)

	require.NoError(t, s.Save(ctx, WithID("ignored"), WithLogLevelPolicy("debug")))
}

func TestEncryptedAgentInfoStore_LoadCorruptYAML(t *testing.T) {
	ctx, encPath := setupEmptyStorePaths(t)

	store, err := storage.NewEncryptedDiskStore(ctx, encPath)
	require.NoError(t, err)
	require.NoError(t, store.Save(bytes.NewReader([]byte("not: valid: yaml: ::: [["))))

	_, err = NewEncryptedAgentInfoStore().Load(ctx)
	require.Error(t, err)
}

// readEncrypted reads and decrypts the on-disk encrypted store at the configured path.
func readEncrypted(t *testing.T, ctx context.Context) map[string]interface{} {
	t.Helper()
	store, err := storage.NewEncryptedDiskStore(ctx, paths.AgentConfigFile())
	require.NoError(t, err)
	reader, err := store.Load()
	require.NoError(t, err)
	defer reader.Close()
	cfg, err := config.NewConfigFrom(reader)
	require.NoError(t, err)
	out := make(map[string]interface{})
	require.NoError(t, cfg.UnpackTo(&out))
	return out
}
