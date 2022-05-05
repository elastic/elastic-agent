// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows
// +build linux windows

package secret

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/google/go-cmp/cmp"
)

func getTestVaultPath() string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	return filepath.Join(dir, "vault", "co.elastic.agent")
}

func getTestOptions() []OptionFunc {
	return []OptionFunc{
		WithVaultPath(getTestVaultPath()),
	}
}

func TestCreate(t *testing.T) {
	vault.DisableRootCheckLinux()

	opts := getTestOptions()

	start := time.Now().UTC()
	keys := []string{"secret1", "secret2", "secret3"}
	for _, key := range keys {
		err := Create(key, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}
	end := time.Now().UTC()

	for _, key := range keys {
		secret, err := Get(key, opts...)
		if err != nil {
			t.Error(err)
		}

		if secret.CreatedOn.Before(start) || secret.CreatedOn.After(end) {
			t.Errorf("invalid created on date/time: %v", secret.CreatedOn)
		}

		diff := cmp.Diff(int(vault.AES256), len(secret.Value))
		if diff != "" {
			t.Error(diff)
		}
	}

	for _, key := range keys {
		err := Remove(key, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}

	os.RemoveAll(filepath.Dir(getTestVaultPath()))
}
