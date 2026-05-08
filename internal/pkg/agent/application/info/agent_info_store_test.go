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
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

// TestSaveOptions exercises every SaveOption against a fresh store and asserts
// both the typed AgentInfo and the on-disk map after a Save and Load.
func TestSaveOptions(t *testing.T) {
	httpCfg := map[string]interface{}{"enabled": true, "host": "127.0.0.1"}
	pprofCfg := map[string]interface{}{"enabled": false}

	cases := []struct {
		name   string
		opt    SaveOption
		verify func(t *testing.T, info *AgentInfo, raw map[string]interface{})
	}{
		{
			name: "WithID",
			opt:  WithID("agent-id"),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				require.Equal(t, "agent-id", info.AgentID)
			},
		},
		{
			name: "WithHeaders",
			opt:  WithHeaders(map[string]string{"X-Test": "yes"}),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				agent := raw["agent"].(map[string]interface{})
				require.Equal(t, map[string]interface{}{"X-Test": "yes"}, agent["headers"])
			},
		},
		{
			name: "WithLogLevelPolicy",
			opt:  WithLogLevelPolicy("debug"),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				require.Equal(t, "debug", info.LogLevelPolicy)
			},
		},
		{
			name: "WithLogLevelOverride",
			opt:  WithLogLevelOverride("warning"),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				require.Equal(t, "warning", info.LogLevelOverride)
			},
		},
		{
			name: "WithEventLoggingToFiles",
			opt:  WithEventLoggingToFiles(true),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				eventData := raw["agent"].(map[string]interface{})["logging"].(map[string]interface{})["event_data"].(map[string]interface{})
				require.Equal(t, true, eventData["to_files"])
			},
		},
		{
			name: "WithEventLoggingToStderr",
			opt:  WithEventLoggingToStderr(true),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				eventData := raw["agent"].(map[string]interface{})["logging"].(map[string]interface{})["event_data"].(map[string]interface{})
				require.Equal(t, true, eventData["to_stderr"])
			},
		},
		{
			name: "WithMonitoringHTTP",
			opt:  WithMonitoringHTTP(httpCfg),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				monitoring := raw["agent"].(map[string]interface{})["monitoring"].(map[string]interface{})
				require.Equal(t, httpCfg, monitoring["http"])
			},
		},
		{
			name: "WithMonitoringPprof",
			opt:  WithMonitoringPprof(pprofCfg),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				monitoring := raw["agent"].(map[string]interface{})["monitoring"].(map[string]interface{})
				require.Equal(t, pprofCfg, monitoring["pprof"])
			},
		},
		{
			name: "WithFleet enabled marks the agent as managed",
			opt:  WithFleet(map[string]interface{}{"enabled": true, "access_api_key": "k"}),
			verify: func(t *testing.T, info *AgentInfo, raw map[string]interface{}) {
				require.False(t, info.isStandalone)
				require.Equal(t, true, raw["fleet"].(map[string]interface{})["enabled"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _ := setupEmptyStorePaths(t)

			require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, tc.opt))

			info, err := NewEncryptedAgentInfoStore().Load(ctx)
			require.NoError(t, err)
			tc.verify(t, info, readEncrypted(t, ctx))
		})
	}
}

// TestSave_PreservesUntouchedFields verifies that fields not addressed by the
// passed options are preserved across a Save (including across two saves
// in a row).
func TestSave_PreservesUntouchedFields(t *testing.T) {
	initial := map[string]interface{}{
		"agent": map[string]interface{}{
			"id":                     "agent-id",
			"headers":                map[string]interface{}{"X-Elastic-Agent-Id": "agent-id"},
			"logging.level_override": "warning",
		},
		"fleet": map[string]interface{}{
			"enabled":        true,
			"access_api_key": "secret-key",
		},
	}
	ctx := setupEncryptedStore(t, initial)

	fleetCfg := configuration.DefaultFleetAgentConfig()
	fleetCfg.Enabled = true
	fleetCfg.AccessAPIKey = "secret-key"

	policySave := func(level string) error {
		return NewEncryptedAgentInfoStore().Save(ctx,
			WithFleet(fleetCfg),
			WithLogLevelPolicy(level),
			WithEventLoggingToFiles(true),
			WithEventLoggingToStderr(false),
		)
	}

	require.NoError(t, policySave("info"))
	require.NoError(t, policySave("debug"))

	info, err := NewEncryptedAgentInfoStore().Load(ctx)
	require.NoError(t, err)
	require.Equal(t, "agent-id", info.AgentID)
	require.Equal(t, map[string]string{"X-Elastic-Agent-Id": "agent-id"}, info.Headers)
	require.Equal(t, "warning", info.LogLevelOverride)
	require.Equal(t, "debug", info.LogLevelPolicy)
}

// TestSave_WithFleetReplacesEntireSection verifies that WithFleet swaps the
// whole fleet subtree (it does not merge with the existing one).
func TestSave_WithFleetReplacesEntireSection(t *testing.T) {
	initial := map[string]interface{}{
		"agent": map[string]interface{}{"id": "agent-id"},
		"fleet": map[string]interface{}{
			"enabled":        true,
			"access_api_key": "old-key",
			"client":         map[string]interface{}{"host": "old.host"},
		},
	}
	ctx := setupEncryptedStore(t, initial)

	newFleet := map[string]interface{}{
		"enabled":        true,
		"access_api_key": "new-key",
	}
	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, WithFleet(newFleet)))

	got := readEncrypted(t, ctx)
	require.Equal(t, newFleet, got["fleet"])
	require.Equal(t, "agent-id", got["agent"].(map[string]interface{})["id"])
}

// TestSave_EmptyValueDeletesKey verifies that passing an empty string to a
// clearable option removes the key from the on-disk map.
func TestSave_EmptyValueDeletesKey(t *testing.T) {
	cases := []struct {
		name      string
		opt       SaveOption
		clearedAt []string // path in the on-disk map that should disappear
	}{
		{
			name:      "WithLogLevelPolicy empty string",
			opt:       WithLogLevelPolicy(""),
			clearedAt: []string{"agent", "logging", "level"},
		},
		{
			name:      "WithLogLevelOverride empty string",
			opt:       WithLogLevelOverride(""),
			clearedAt: []string{"agent", "logging", "level_override"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := setupEncryptedStore(t, map[string]interface{}{
				"agent": map[string]interface{}{
					"id":                     "agent-id",
					"logging.level":          "info",
					"logging.level_override": "warning",
				},
			})

			require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx, tc.opt))

			raw := readEncrypted(t, ctx)
			cur, ok := raw[tc.clearedAt[0]].(map[string]interface{})
			require.True(t, ok)
			for _, seg := range tc.clearedAt[1 : len(tc.clearedAt)-1] {
				cur, ok = cur[seg].(map[string]interface{})
				require.True(t, ok)
			}
			_, exists := cur[tc.clearedAt[len(tc.clearedAt)-1]]
			require.False(t, exists)

			require.Equal(t, "agent-id", raw["agent"].(map[string]interface{})["id"])
		})
	}
}

// TestSave_NoOpsLeavesNoFile verifies that calling Save with no options does
// not create the on-disk file.
func TestSave_NoOpsLeavesNoFile(t *testing.T) {
	ctx, encPath := setupEmptyStorePaths(t)
	require.NoFileExists(t, encPath)

	require.NoError(t, NewEncryptedAgentInfoStore().Save(ctx))
	require.NoFileExists(t, encPath)
}

// TestNullAgentInfoStore verifies that the no-op variant returns an empty
// AgentInfo and accepts (and discards) any save options.
func TestNullAgentInfoStore(t *testing.T) {
	var s NullAgentInfoStore
	ctx := context.Background()

	info, err := s.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Empty(t, info.AgentID)

	require.NoError(t, s.Save(ctx, WithID("ignored"), WithLogLevelPolicy("debug")))
}

// TestErrors covers all error paths surfaced by Load and Save.
func TestErrors(t *testing.T) {
	t.Run("Load: corrupt YAML", func(t *testing.T) {
		ctx, encPath := setupEmptyStorePaths(t)
		store, err := storage.NewEncryptedDiskStore(ctx, encPath)
		require.NoError(t, err)
		require.NoError(t, store.Save(bytes.NewReader([]byte("not: valid: yaml: ::: [["))))

		_, err = NewEncryptedAgentInfoStore().Load(ctx)
		require.Error(t, err)
	})

	t.Run("Save: intermediate path holds a non-map value", func(t *testing.T) {
		ctx := setupEncryptedStore(t, map[string]interface{}{
			"agent": "this should be a map but isn't",
		})

		err := NewEncryptedAgentInfoStore().Save(ctx, WithLogLevelPolicy("debug"))
		require.Error(t, err)
	})
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
