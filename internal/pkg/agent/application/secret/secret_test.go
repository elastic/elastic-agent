// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package secret

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
)

func getTestVaultPath(t *testing.T) string {
	dir := t.TempDir()
	return filepath.Join(dir, "vault", "co.elastic.agent")
}

func getTestOptions(t *testing.T) []OptionFunc {
	return []OptionFunc{
		WithVaultPath(getTestVaultPath(t)),
	}
}

func TestCreate(t *testing.T) {
	opts := getTestOptions(t)

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	start := time.Now().UTC()
	keys := []string{"secret1", "secret2", "secret3"}
	for _, key := range keys {
		err := Create(ctx, key, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}
	end := time.Now().UTC()

	for _, key := range keys {
		secret, err := Get(ctx, key, opts...)
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
		err := Remove(ctx, key, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}

	os.RemoveAll(filepath.Dir(getTestVaultPath(t)))
}
