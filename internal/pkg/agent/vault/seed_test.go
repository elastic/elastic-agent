// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package vault

import (
	"context"
	"encoding/binary"
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

func TestGetSeedV1(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	// check the test prerequisites
	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// seed is not yet created
	if _, err := getSeedV1(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	// should be not found
	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// create seed manually
	seed, err := aesgcm.NewKey(aesgcm.AES256)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(fp, seed, 0600)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(fp); err != nil {
		t.Fatal(err)
	}

	b, err := getSeedV1(dir)
	if err != nil {
		t.Fatal(err)
	}

	if seedFileSize != len(b) {
		t.Errorf("expected seed file size to be %d, got: %d", seedFileSize, len(b))
	}

	diff := cmp.Diff(seed, b)
	if diff != "" {
		t.Error(diff)
	}
}

func TestGetSeedV2(t *testing.T) {
	dir := t.TempDir()

	fp := filepath.Join(dir, seedFileV2)

	// check the test prerequisites
	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// seed is not yet created
	if _, _, err := getSeedV2(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// should be not found
	if _, err := os.Stat(fp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	// create seed manually
	seed, err := aesgcm.NewKey(aesgcm.AES256)
	if err != nil {
		t.Fatal(err)
	}
	l := make([]byte, 4)
	binary.LittleEndian.PutUint32(l, uint32(defaultSaltSizeV2))
	err = os.WriteFile(fp, append(seed, l...), 0600)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(fp); err != nil {
		t.Fatal(err)
	}

	b, saltSize, err := getSeedV2(dir)
	if err != nil {
		t.Fatal(err)
	}

	if seedFileSize != len(b) {
		t.Errorf("expected seed length to be %d, got: %d", seedFileSize, len(b))
	}
	if saltSize != defaultSaltSizeV2 {
		t.Errorf("expected salt size: %d got: %d", defaultSaltSizeV2, saltSize)
	}

	diff := cmp.Diff(seed, b)
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
				seed, _, err := createSeedIfNotExists(dir)
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
