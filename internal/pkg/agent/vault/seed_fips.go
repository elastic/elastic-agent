// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package vault

import (
	"errors"
	"fmt"
)

func getSeed(path string) ([]byte, int, error) {
	b, saltSize, err := getSeedV2(path)
	if err != nil {
		return nil, 0, err
	}
	if saltSize < 16 {
		return nil, 0, fmt.Errorf("detected salt size %d is too low: %w", saltSize, errors.ErrUnsupported)
	}
	return b, saltSize, nil
}
