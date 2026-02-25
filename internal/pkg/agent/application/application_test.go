// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/limits"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestMergeFleetConfig(t *testing.T) {
	testutils.InitStorage(t)

	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"enabled":        true,
			"kibana":         map[string]interface{}{"host": "demo"},
			"access_api_key": "123",
		},
		"agent": map[string]interface{}{
			"grpc": map[string]interface{}{
				"port": uint16(6790),
			},
		},
	}

	rawConfig := config.MustNewConfigFrom(cfg)
	storage, conf, err := mergeFleetConfig(context.Background(), rawConfig)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}

func TestLimitsLog(t *testing.T) {
	log, obs := loggertest.New("TestLimitsLog")
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	_, _, _, err := New(
		ctx,
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{}, // info.AgentInfo
		nil,               // coordinator.ReExecManager
		nil,               // apm.Tracer
		true,              // testingMode
		time.Millisecond,  // fleetInitTimeout
		true,              // disable monitoring
		nil,               // no configuration overrides
		nil,
	)
	require.NoError(t, err)

	old := limits.LimitsConfig{
		GoMaxProcs: 0,
	}
	new := limits.LimitsConfig{
		GoMaxProcs: 99,
	}

	// apply is also called inside `New`, however there is no log line because the config file
	// does not define `agent.limits.go_max_procs` and the default value does not change.
	// so, no callback, no log line.

	// now we trigger the log line
	err = limits.Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 99`))
	require.NoError(t, err)

	expLogLine := fmt.Sprintf("agent limits have changed: %+v -> %+v", old, new)
	logs := obs.FilterMessageSnippet(expLogLine)
	require.Equalf(t, 1, logs.Len(), "expected one log message about limits change")
}

func TestApplicationStandaloneEncrypted(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "encrypted disk storage does not use NewGCMWithRandomNonce.")
	log, _ := loggertest.New("TestApplicationStandaloneEncrypted")

	cfgPath := paths.Config()
	t.Cleanup(func() { paths.SetConfig(cfgPath) })

	paths.SetConfig(t.TempDir())
	err := os.WriteFile(paths.ConfigFile(), []byte(`agent:
  features:
    encrypted_config:
      enabled: true
  logging:
    level: debug`), 0640)
	require.NoError(t, err)

	t.Log("Ensure New encrypts config")
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		nil,
		nil,
	)
	require.NoError(t, err)

	encBytes, err := os.ReadFile(paths.AgentConfigFile())
	require.NoError(t, err)

	ymlBytes, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, ymlBytes, "unexpected contents in elastic-agent.yml")

	t.Log("Ensure New does not alter contents when no changes are made")
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		nil,
		nil,
	)
	require.NoError(t, err)
	encBytes2, err := os.ReadFile(paths.AgentConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, encBytes, encBytes2, "fleet.enc contents have chagned")

	ymlBytes, err = os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, ymlBytes, "unexpected contents in elastic-agent.yml")

	t.Log("Change elastic-agent.yml to have same contents with different structure, should not re-encrypt")
	err = os.WriteFile(paths.ConfigFile(), []byte(`agent:
  features:
    encrypted_config:
      enabled: true`), 0640)
	require.NoError(t, err)

	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		nil,
		nil,
	)
	require.NoError(t, err)
	encBytes3, err := os.ReadFile(paths.AgentConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, encBytes, encBytes3, "fleet.enc contents have chagned")

	ymlBytes, err = os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.NotEqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, ymlBytes, "unexpected contents in elastic-agent.yml")

	t.Log("Ensure that setting encrypted_config to false works")
	err = os.WriteFile(paths.ConfigFile(), []byte(`agent:
  features:
    encrypted_config:
      enabled: false
  logging:
    level: debug`), 0640)
	require.NoError(t, err)

	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		nil,
		nil,
	)
	require.NoError(t, err)
}

func TestHasEncryptedStandaloneConfigChanged(t *testing.T) {
	log, _ := loggertest.New("TestHasEncryptedStandaloneConfigChanged")
	tests := []struct {
		name     string
		contents []byte
		expect   bool
	}{{
		name:     "no change",
		contents: storage.DefaultAgentEncryptedStandaloneConfig,
		expect:   false,
	}, {
		name: "contents change",
		contents: []byte(`agent:
  features:
    encrypted_config:
      enabled: true
    fqdn:
      enabled: true
`),
		expect: true,
	}, {
		name:     "no file contents",
		contents: []byte{},
		expect:   true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.yml")
			err := os.WriteFile(path, tt.contents, 0640)
			require.NoError(t, err)
			changed := hasEncryptedStandaloneConfigChanged(log, path)
			require.Equal(t, tt.expect, changed)
		})
	}
}

func TestApplicationStandaloneEncryptedWithFleetEnabled(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "encrypted disk storage does not use NewGCMWithRandomNonce.")
	log, _ := loggertest.New("TestApplicationStandaloneEncryptedWithFleetEnabled")

	cfgPath := paths.Config()
	t.Cleanup(func() { paths.SetConfig(cfgPath) })
	paths.SetConfig(t.TempDir())

	p, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "_meta", "elastic-agent.fleet.yml"))
	require.NoError(t, err)
	err = os.WriteFile(paths.ConfigFile(), p, 0640)
	require.NoError(t, err)

	isRoot, err := utils.HasRoot()
	require.NoError(t, err)
	err = secret.CreateAgentSecret(t.Context(), vault.WithUnprivileged(!isRoot), vault.WithVaultPath(filepath.Join(paths.Config(), paths.DefaultAgentVaultPath)))
	require.NoError(t, err)
	encStore, err := storage.NewEncryptedDiskStore(t.Context(), filepath.Join(paths.Config(), paths.DefaultAgentFleetFile), storage.WithVaultPath(filepath.Join(paths.Config(), paths.DefaultAgentVaultPath)))
	require.NoError(t, err)
	err = encStore.Save(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "exampleKey"
  host: https://localhost:8220`))
	require.NoError(t, err)

	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		nil,
		nil,
	)
	require.NoError(t, err)

	ymlBytes, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, p, ymlBytes, "unexpected contents in elastic-agent.yml")
}
