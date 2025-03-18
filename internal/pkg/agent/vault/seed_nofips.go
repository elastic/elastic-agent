// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package vault

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

// getSeed returns the seed from the v1 .seed file
// or fs.ErrNotExist if the bytecount does not match
func getSeed(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()

	// Non fips only supports V1 seed
	b, err := getSeedV1(path)
	if err != nil {
		return nil, 0, err
	}
	return b, saltSizeV1, nil
}

// checkSalt is a nop as V2 seeds are disabled for non-FIPS agents
func checkSalt(_ int) error {
	return nil
}

// createSeedIfNotExists returns the seed from the v1 .seed file
// If the seed file does not exist it will create and write a new v1 seed file.
func createSeedIfNotExists(path string) ([]byte, int, error) {
	mxSeed.Lock()
	defer mxSeed.Unlock()

	pass, err := getSeedV1(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, err
		}
	}
	if len(pass) != 0 {
		return pass, saltSizeV1, nil
	}

	seed, err := aesgcm.NewKey(aesgcm.AES256)
	if err != nil {
		return nil, 0, err
	}
	err = os.WriteFile(filepath.Join(path, seedFile), seed, 0600)
	if err != nil {
		return nil, 0, err
	}

	return seed, saltSizeV1, nil
}
