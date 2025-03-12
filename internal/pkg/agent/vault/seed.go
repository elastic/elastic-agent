// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

const (
	// seedFile is len(aesgcm.AES256) and contains only the random seed
	// A default salt size of 8 is used with this seed file
	seedFile = ".seed"
	// seedFileV2 is len(aesgcm.AES256+4) and contains the random seed followed by a non-zero salt size (little endian uint32)
	seedFileV2 = ".seedV2"
)

const (
	saltSizeV1      = 8
	defaultSaltSize = 16
)

var (
	mxSeed sync.Mutex
)

func getSeedV1(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)

	mxSeed.Lock()
	defer mxSeed.Unlock()

	b, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("could not read seed file: %w", err)
	}

	// return fs.ErrNotExist if invalid length of bytes returned
	if len(b) != int(aesgcm.AES256) {
		return nil, fmt.Errorf("invalid seed length, expected: %v, got: %v: %w", int(aesgcm.AES256), len(b), fs.ErrNotExist)
	}
	return b, nil
}

func getSeedV2(path string) ([]byte, int, error) {
	fp := filepath.Join(path, seedFileV2)

	mxSeed.Lock()
	defer mxSeed.Unlock()

	b, err := os.ReadFile(fp)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read seed file: %w", err)
	}

	// return fs.ErrNotExist if invalid length of bytes returned
	if len(b) != int(aesgcm.AES256)+4 {
		return nil, 0, fmt.Errorf("invalid seed length, expected: %v, got: %v: %w", int(aesgcm.AES256)+4, len(b), fs.ErrNotExist)
	}
	pass := b[0:int(aesgcm.AES256)]
	saltSize := binary.LittleEndian.Uint32(b[int(aesgcm.AES256):])
	if saltSize == 0 {
		return nil, 0, fmt.Errorf("salt size 0 detected: %w", fs.ErrNotExist)
	}
	return pass, int(saltSize), nil
}

func createSeedIfNotExists(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()
	pass, saltSize, err := getSeed(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, err
		}
	}
	if len(pass) != 0 {
		return pass, saltSize, nil
	}

	seed, err := aesgcm.NewKey(aesgcm.AES256)
	if err != nil {
		return nil, 0, err
	}
	l := make([]byte, 4)
	binary.LittleEndian.PutUint32(l, uint32(defaultSaltSize))

	err = os.WriteFile(filepath.Join(path, seedFileV2), append(seed, l...), 0600)
	if err != nil {
		return nil, 0, err
	}

	return seed, defaultSaltSize, nil
}

func getOrCreateSeed(path string, readonly bool) ([]byte, int, error) {
	if readonly {
		return getSeed(path)
	}
	return createSeedIfNotExists(path)
}
