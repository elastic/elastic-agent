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
)

func TestAgentIDStandaloneWorks(t *testing.T) {
	if runtime.GOOS == "darwin" {
		// vault requres extra perms on mac
		t.Skip()
	}
	// create a new encrypted disk store
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tmpPath := t.TempDir()
	paths.SetConfig(tmpPath)

	vaultPath := filepath.Join(tmpPath, "vault")
	err := secret.CreateAgentSecret(ctx, vault.WithVaultPath(vaultPath))
	require.NoError(t, err)

	setID := "test-id"
	testCfg := map[string]interface{}{
		"agent": map[string]interface{}{
			"id": setID,
		},
	}
	saveToStateStore(t, tmpPath, testCfg)

	got, err := NewAgentInfo(ctx, false)
	require.NoError(t, err)
	t.Logf("got: %#v", got)

	// check the ID to make sure we've opened the fleet config properly
	require.Equal(t, setID, got.agentID)

	// no fleet config, should be standalone
	require.True(t, got.isStandalone)

	// update fleet config, this time in managed mode
	testCfg = map[string]interface{}{
		"agent": map[string]interface{}{
			"id": setID,
		},
		"fleet": map[string]interface{}{
			"enabled": true,
		},
	}
	saveToStateStore(t, tmpPath, testCfg)

	got, err = NewAgentInfo(ctx, false)
	require.NoError(t, err)
	t.Logf("got: %#v", got)
	require.False(t, got.isStandalone)

}

func saveToStateStore(t *testing.T, tmpPath string, in map[string]interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	encPath := filepath.Join(tmpPath, "fleet.enc")
	store, err := storage.NewEncryptedDiskStore(ctx, encPath)
	require.NoError(t, err)

	rawYml, err := yaml.Marshal(in)
	require.NoError(t, err)

	reader := bytes.NewReader(rawYml)

	err = store.Save(reader)
	require.NoError(t, err)
}
