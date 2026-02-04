// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFileVaultRekey(t *testing.T) {
	const key = "foo"

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	vaultPath := getTestFileVaultPath(t)
	options, err := ApplyOptions(WithVaultPath(vaultPath))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewFileVault(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	err = v.Set(ctx, key, []byte("bar"))
	if err != nil {
		t.Fatal(err)
	}

	// Read seed file value
	seedPath := filepath.Join(vaultPath, seedFileV2)
	seedFileBytes, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(seedFileV2Size, len(seedFileBytes))
	if diff != "" {
		t.Fatal(diff)
	}

	// Remove the .seedV2 file.
	// This will cause the vault seed to be reinitialized for the new vault instance
	err = os.Remove(seedPath)
	if err != nil {
		t.Fatal(err)
	}

	// The vault with the new seed
	v2, err := NewFileVault(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()

	// The key should be not found
	_, err = v2.Get(ctx, key)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
