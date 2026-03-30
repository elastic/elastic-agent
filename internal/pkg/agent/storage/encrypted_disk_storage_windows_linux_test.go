// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux || windows

package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
)

const (
	testConfigFile = "someconfig.enc"
	vaultDir       = "vault"
)

func TestEncryptedDiskStorageWindowsLinuxLoad(t *testing.T) {
	dir := t.TempDir()

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	fp := filepath.Join(dir, testConfigFile)
	s, err := NewEncryptedDiskStore(ctx, fp, WithVaultPath(dir))
	require.NoError(t, err)

	// Test that the file loads and doesn't create vault
	r, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	// Expect empty content from the reader
	diff := cmp.Diff(0, len(b))
	if diff != "" {
		t.Error(diff)
	}

	// Expect no vault directory was created
	vdir := filepath.Join(dir, vaultDir)
	if _, err := os.Stat(vdir); !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// Save some data
	// expect fs.PathError, no agent secret key was created yet
	data := []byte("foobar config\ndata")
	err = s.Save(bytes.NewBuffer(data))
	if err != nil {
		var perr *fs.PathError
		if !errors.As(err, &perr) {
			t.Fatal(err)
		}
	}

	// Create agent secret
	err = secret.CreateAgentSecret(ctx, vault.WithVaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}

	// Save agent secret, expected to be saved
	err = s.Save(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	// Expect the stored file to exist
	exists, err := s.Exists()
	if err != nil {
		t.Fatal(err)
	}
	diff = cmp.Diff(true, exists)
	if diff != "" {
		t.Error(diff)
	}

	// Load content
	nr, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close()

	b, err = io.ReadAll(nr)
	if err != nil {
		t.Fatal(err)
	}

	// Expect the content to match
	diff = cmp.Diff(b, data)
	if diff != "" {
		t.Error(diff)
	}
}
