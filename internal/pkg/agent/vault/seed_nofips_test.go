// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

func TestGetSeedReturnsV1File(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, seedFile)

	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	seed, err := aesgcm.NewKey(aesgcm.AES256)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(fp, seed, 0600)
	if err != nil {
		t.Fatal(err)
	}

	b, saltSize, err := getSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(seed, b); diff != "" {
		t.Error(diff)
	}
	if saltSize != saltSizeV1 {
		t.Errorf("expected salt size: %d got: %d", saltSizeV1, saltSize)
	}
}

func TestCreateSeedIfNotExists(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)
	fpV2 := filepath.Join(dir, seedFileV2)

	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := os.Stat(fpV2); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	b, saltSize, err := createSeedIfNotExists(dir)
	if err != nil {
		t.Fatal(err)
	}

	// V2 file should exist
	if _, err := os.Stat(fpV2); err != nil {
		t.Fatal(err)
	}
	// V1 file should exist
	if _, err := os.Stat(fp); err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(int(aesgcm.AES256), len(b))
	if diff != "" {
		t.Error(diff)
	}
	if saltSize != defaultSaltSize {
		t.Errorf("expected salt size: %d got: %d", defaultSaltSize, saltSize)
	}
}
