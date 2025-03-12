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
	// seedFileV2 is len(aesgcm.AES256)+4 and contains the random seed followed by a non-zero salt size (little endian uint32)
	seedFileV2     = ".seedV2"
	seedFileV2Size = int(aesgcm.AES256) + 4
)

const (
	saltSizeV1      = 8
	defaultSaltSize = 16
)

var (
	mxSeed sync.Mutex
)

func getSeed(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()

	// Prefer V2 seeds
	b, saltSize, errV2 := getSeedV2(path)
	if errV2 == nil {
		return b, saltSize, nil
	}
	// Fallback to V1 seed
	b, errV1 := getSeedV1(path)
	if errV1 == nil {
		return b, saltSizeV1, nil
	}
	return nil, 0, errors.Join(errV2, errV1)
}

// getSeedV2 will read a seedV2 file and return the passphrase and saltSize
// Will return fs.ErrNotExists if the byte count does not match, or saltSize is 0
// when in FIPS mode will return fs.ErrUnsupported when saltSize is non-zero but less then 16
func getSeedV2(path string) ([]byte, int, error) {
	fp := filepath.Join(path, seedFileV2)

	b, err := os.ReadFile(fp)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read seed file: %w", err)
	}

	// return fs.ErrNotExist if invalid length of bytes returned
	if len(b) != seedFileV2Size {
		return nil, 0, fmt.Errorf("invalid seed length, expected: %v, got: %v: %w", seedFileV2Size, len(b), fs.ErrNotExist)
	}
	pass := b[0:int(aesgcm.AES256)]
	saltSize := binary.LittleEndian.Uint32(b[int(aesgcm.AES256):])
	if saltSize == 0 {
		return nil, 0, fmt.Errorf("salt size 0 detected: %w", fs.ErrNotExist)
	}
	if err := checkSalt(int(saltSize)); err != nil {
		return nil, 0, err
	}
	return pass, int(saltSize), nil
}

func createSeedIfNotExists(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()

	// Prefer reading V2 seeds
	pass, saltSize, err := getSeedV2(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, err
		}
	}
	if len(pass) != 0 {
		return pass, saltSize, nil
	}

	// V1 seed fallback
	// getSeedV1 will return ErrNotExist when in FIPS mode.
	pass, err = getSeedV1(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, err
		}
	}
	if len(pass) != 0 {
		return pass, saltSizeV1, nil
	}

	// Create V2 seed
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
