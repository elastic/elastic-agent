// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package vault

import (
	"encoding/binary"
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
	seedFile     = ".seed"
	seedFileSize = int(aesgcm.AES256)
	// seedFileV2 is len(aesgcm.AES256)+4 and contains the random seed followed by a non-zero salt size (little endian uint32)
	seedFileV2     = ".seedV2"
	seedFileV2Size = seedFileSize + 4
)

const (
	saltSizeV1        = 8
	defaultSaltSizeV2 = 16
)

var (
	mxSeed sync.Mutex
)

// getSeedV1 will read the V1 .seed file
// Will return fs.ErrNotExists if the bytecount does not match
func getSeedV1(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)

	b, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("could not read seed file: %w", err)
	}

	// return fs.ErrNotExist if invalid length of bytes returned
	if len(b) != seedFileSize {
		return nil, fmt.Errorf("invalid seed length, expected: %v, got: %v: %w", seedFileSize, len(b), fs.ErrNotExist)
	}
	return b, nil
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
	pass := b[0:seedFileSize]
	saltSize := binary.LittleEndian.Uint32(b[seedFileSize:])
	if saltSize == 0 {
		return nil, 0, fmt.Errorf("salt size 0 detected: %w", fs.ErrNotExist)
	}
	if err := checkSalt(int(saltSize)); err != nil {
		return nil, 0, err
	}
	return pass, int(saltSize), nil
}

func getOrCreateSeed(path string, readonly bool) ([]byte, int, error) {
	if readonly {
		return getSeed(path)
	}
	return createSeedIfNotExists(path)
}
