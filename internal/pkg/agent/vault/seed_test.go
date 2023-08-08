// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package vault

import (
	"context"
	"encoding/hex"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestGetSeed(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	require.NoFileExists(t, fp)

	// seed is not yet created
	_, err := getSeed(dir)

	// should be not found
	require.ErrorIs(t, err, fs.ErrNotExist)

	b, err := createSeedIfNotExists(dir)
	assert.NoError(t, err)

	require.FileExists(t, fp)

	diff := cmp.Diff(int(AES256), len(b))
	if diff != "" {
		t.Error(diff)
	}

	// try get seed
	gotSeed, err := getSeed(dir)
	assert.NoError(t, err)

	diff = cmp.Diff(b, gotSeed)
	if diff != "" {
		t.Error(diff)
	}
}

func TestCreateSeedIfNotExists(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	assert.NoFileExists(t, fp)

	b, err := createSeedIfNotExists(dir)
	assert.NoError(t, err)

	require.FileExists(t, fp)

	diff := cmp.Diff(int(AES256), len(b))
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
	assert.NoError(t, err)

	set := make(map[string]struct{})

	for _, item := range res {
		set[hex.EncodeToString(item)] = struct{}{}
	}

	if len(set) > 1 {
		t.Fatalf("more than one seeds were created: %#v\n", set)
	}

}
