// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"
)

func getTestVaultPath(t *testing.T) string {
	dir := t.TempDir()
	return filepath.Join(dir, "vault")
}

func TestVaultRekey(t *testing.T) {
	const key = "foo"

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	vaultPath := getTestVaultPath(t)
	v, err := New(ctx, vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	err = v.Set(ctx, key, []byte("bar"))
	if err != nil {
		t.Fatal(err)
	}

	// Read seed file value
	seedPath := filepath.Join(vaultPath, ".seed")
	seedBytes, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(int(AES256), len(seedBytes))
	if diff != "" {
		t.Fatal(diff)
	}

	// Remove the .seed file.
	// This will cause the vault seed to be reinitialized for the new vault instance
	err = os.Remove(seedPath)
	if err != nil {
		t.Fatal(err)
	}

	// The vault with the new seed
	v2, err := New(ctx, vaultPath)
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

func TestVault(t *testing.T) {
	vaultPath := getTestVaultPath(t)

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	v, err := New(ctx, vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	defer v.Close()

	const (
		key1 = "key1"
		key2 = "key2"
		key3 = "key3"

		val1 = "value1"
		val2 = "value22"
		val3 = "value3"
	)

	keys := []string{key1, key2, key3}
	vals := []string{val1, val2, val3}

	// Test that keys do not exists
	for _, key := range keys {
		exists, err := v.Exists(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		diff := cmp.Diff(exists, false)
		if diff != "" {
			t.Fatal(diff)
		}
	}

	// Create keys, except the last one
	for i := 0; i < len(keys)-1; i++ {
		err := v.Set(ctx, keys[i], []byte(vals[i]))
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify the keys that were created now exist
	for i := 0; i < len(keys)-1; i++ {
		exists, err := v.Exists(ctx, keys[i])
		if err != nil {
			t.Fatal(err)
		}
		diff := cmp.Diff(exists, true)
		if diff != "" {
			t.Fatal(diff)
		}
	}

	// Verify the keys values
	for i := 0; i < len(keys)-1; i++ {
		b, err := v.Get(ctx, keys[i])
		if err != nil {
			t.Fatal(err)
		}
		diff := cmp.Diff(b, []byte(vals[i]))
		if diff != "" {
			t.Fatal(diff)
		}
	}

	// Verify that the last key that was not creates still doesn't exists
	exists, err := v.Exists(ctx, keys[len(keys)-1])
	if err != nil {
		t.Fatal(err)
	}
	diff := cmp.Diff(exists, false)
	if diff != "" {
		t.Fatal(diff)
	}

	// Delete the first key
	err = v.Remove(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}

	// Verify that just deleted key doesn't exist anymore
	exists, err = v.Exists(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}

	diff = cmp.Diff(exists, false)
	if diff != "" {
		t.Fatal(diff)
	}
}

type secret struct {
	Value     []byte    `json:"v"` // binary value
	CreatedOn time.Time `json:"t"` // date/time the secret was created on
}

func TestVaultConcurrent(t *testing.T) {
	const (
		parallel   = 15
		iterations = 7

		key = `secret`
	)

	vaultPath := getTestVaultPath(t)

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	for i := 0; i < iterations; i++ {
		g, _ := errgroup.WithContext(context.Background())
		for j := 0; j < parallel; j++ {
			g.Go(func() error {
				return doCrud(t, ctx, vaultPath, key)
			})
		}
		err := g.Wait()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func doCrud(t *testing.T, ctx context.Context, vaultPath, key string) error {
	v, err := New(ctx, vaultPath)
	if err != nil {
		return fmt.Errorf("could not create new vault: %w", err)
	}
	defer v.Close()

	// Create new AES256 key
	k, err := NewKey(AES256)
	if err != nil {
		return err
	}

	secret := secret{
		Value:     k,
		CreatedOn: time.Now().UTC(),
	}

	b, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("could not marshal secret: %w", err)
	}

	err = v.Set(ctx, key, b)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	sec, err := v.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	_ = sec

	return nil
}
