// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows
// +build linux windows

package vault

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

const seedFile = ".seed"

func getSeed(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)
	b, err := ioutil.ReadFile(fp)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		} else {
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
