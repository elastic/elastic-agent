// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package vault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

func getSeedV1(path string) ([]byte, error) {
	fp := filepath.Join(path, seedFile)

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

func checkSalt(_ int) error {
	return nil
}
