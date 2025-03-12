// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package vault

import (
	"errors"
	"fmt"
	"io/fs"
)

// getSeedV1 will return an fs.ErrNotExist in FIPS mode.
func getSeedV1(path string) ([]byte, error) {
	return nil, fmt.Errorf("seed V1 format is unsupported in FIPS mode: %w", fs.ErrNotExist)
}

func checkSalt(size int) error {
	if size < 16 {
		return fmt.Errorf("expected salt to be at least 16: %w", errors.ErrUnsupported)
	}
	return nil
}
