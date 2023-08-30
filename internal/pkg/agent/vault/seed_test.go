// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !darwin

package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

func TestGetSeed(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	// check the test prerequisites
	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// seed is not yet created
	if _, err := getSeed(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// should be not found
	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	b, err := createSeedIfNotExists(dir)
	if err != nil {
		t.Fatal(err)
	}

	// file should exist
	if _, err := os.Stat(fp); err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(int(aesgcm.AES256), len(b))
	if diff != "" {
		t.Error(diff)
	}

	// try get seed
	gotSeed, err := getSeed(dir)
	if err != nil {
		t.Fatal(err)
	}

	diff = cmp.Diff(b, gotSeed)
	if diff != "" {
		t.Error(diff)
	}
}

func TestCreateSeedIfNotExists(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	b, err := createSeedIfNotExists(dir)
	if err != nil {
		t.Fatal(err)
	}

	// file should exist
	if _, err := os.Stat(fp); err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(int(aesgcm.AES256), len(b))
	if diff != "" {
		t.Error(diff)
	}
}

func TestCreateSeedIfNotExistsRace(t *testing.T) {
	var err error

	dir := t.TempDir()

	g, _ := errgroup.WithContext(context.Background())

	const count = 10
	res := make([][]byte, count)
	var mx sync.Mutex

	for i := 0; i < count; i++ {
		g.Go(func(idx int) func() error {
			return func() error {
				seed, err := createSeedIfNotExists(dir)
				mx.Lock()
				res[idx] = seed
				mx.Unlock()
				return err
			}
		}(i))
	}

	err = g.Wait()
	if err != nil {
		t.Fatal(err)
	}

	set := make(map[string]struct{})

	for _, item := range res {
		set[hex.EncodeToString(item)] = struct{}{}
	}

	if len(set) > 1 {
		t.Fatalf("more than one seeds were created: %#v\n", set)
	}

}
