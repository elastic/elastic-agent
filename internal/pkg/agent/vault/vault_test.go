// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows
// +build linux windows

package vault

import (
	"path/filepath"

	"testing"

	"github.com/google/go-cmp/cmp"
)

func getTestVaultPath(t *testing.T) string {
	dir := t.TempDir()
	return filepath.Join(dir, "vault")
}

func TestVault(t *testing.T) {

	// Disable root check, because the tests are not running as sudo
	DisableRootCheck()

	vaultPath := getTestVaultPath(t)

	v, err := New(vaultPath)
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
		exists, err := v.Exists(key)
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
		err := v.Set(keys[i], []byte(vals[i]))
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify the keys that were created now exist
	for i := 0; i < len(keys)-1; i++ {
		exists, err := v.Exists(keys[i])
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
		b, err := v.Get(keys[i])
		if err != nil {
			t.Fatal(err)
		}
		diff := cmp.Diff(b, []byte(vals[i]))
		if diff != "" {
			t.Fatal(diff)
		}
	}

	// Verify that the last key that was not creates still doesn't exists
	exists, err := v.Exists(keys[len(keys)-1])
	if err != nil {
		t.Fatal(err)
	}
	diff := cmp.Diff(exists, false)
	if diff != "" {
		t.Fatal(diff)
	}

	// Delete the first key
	err = v.Remove(keys[0])
	if err != nil {
		t.Fatal(err)
	}

	// Verify that just deleted key doesn't exist anymore
	exists, err = v.Exists(keys[0])
	if err != nil {
		t.Fatal(err)
	}

	diff = cmp.Diff(exists, false)
	if diff != "" {
		t.Fatal(diff)
	}
}
