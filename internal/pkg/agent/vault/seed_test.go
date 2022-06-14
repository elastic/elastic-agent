// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows
// +build linux windows

package vault

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

func TestGetSeed(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	assert.NoFileExists(t, fp)

	b, err := getSeed(dir)
	assert.NoError(t, err)

	assert.FileExists(t, fp)

	diff := cmp.Diff(int(AES256), len(b))
	if diff != "" {
		t.Error(diff)
	}
}

func TestGetSeedRace(t *testing.T) {
	var err error

	dir := t.TempDir()

	g, _ := errgroup.WithContext(context.Background())

	const count = 10
	res := make([][]byte, count)
	var mx sync.Mutex

	for i := 0; i < count; i++ {
		g.Go(func(idx int) func() error {
			return func() error {
				seed, err := getSeed(dir)
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
