// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

// getSeed returns the seed and salt size from the V2 seed file.
// If the byte count does not match, or a 0 length salt is detected fs.ErrNotExist will be returned.
func getSeed(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()

	// FIPS only supports V2
	b, saltSize, err := getSeedV2(path)
	if err != nil {
		return nil, 0, err
	}
	return b, saltSize, nil
}

// checkSalt ensures the salt size is at least 16 bytes.
func checkSalt(size int) error {
	if size < defaultSaltSizeV2 {
		return fmt.Errorf("expected salt to be at least %d: %w", defaultSaltSizeV2, errors.ErrUnsupported)
	}
	return nil
}

// createSeedIfNotExists returns the seed and salt size from the V2 seed file.
// If the seed file does not exist it will create and write a new V2 seed file with a salt size of 16.
func createSeedIfNotExists(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()

	pass, saltSize, err := getSeedV2(path)
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
	binary.LittleEndian.PutUint32(l, uint32(defaultSaltSizeV2))

	err = os.WriteFile(filepath.Join(path, seedFileV2), append(seed, l...), 0600)
	if err != nil {
		return nil, 0, err
	}

	return seed, defaultSaltSizeV2, nil
}
