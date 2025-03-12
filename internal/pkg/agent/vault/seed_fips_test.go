// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

func TestGetSeedFailsV1File(t *testing.T) {
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

	_, _, err = getSeed(dir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIPS mode must not read v1 seeds. expected error %v to be os.ErrNotExist", err)
	}
}
