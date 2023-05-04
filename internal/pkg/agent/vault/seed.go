// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

const (
	seedFile = ".seed"
)

var (
	mxSeed sync.Mutex
)

func getSeed(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)

	mxSeed.Lock()
	defer mxSeed.Unlock()

	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("could not read seed file: %w", err)
	}

	// return fs.ErrNotExists if invalid length of bytes returned
	if len(b) != int(AES256) {
		return nil, fmt.Errorf("invalid seed length, expected: %v, got: %v: %w", int(AES256), len(b), fs.ErrNotExist)
	}
	return b, nil
}

func createSeedIfNotExists(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)

	mxSeed.Lock()
	defer mxSeed.Unlock()

	b, err := ioutil.ReadFile(fp)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	if len(b) != 0 {
		return b, nil
	}

	seed, err := NewKey(AES256)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(fp, seed, 0600)
	if err != nil {
		return nil, err
	}

	return seed, nil
}

func getOrCreateSeed(path string, readonly bool) ([]byte, error) {
	if readonly {
		return getSeed(path)
	}
	return createSeedIfNotExists(path)
}
