// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package crypto

import (
	"errors"
)

// Validate the options for encoding and decoding values.
func (o *Option) Validate() error {
	if o.IVLength == 0 {
		return errors.New("IVLength must be superior to 0")
	}

	if o.SaltLength == 0 {
		return errors.New("SaltLength must be superior to 0")
	}

	if o.IterationsCount == 0 {
		return errors.New("IterationsCount must be superior to 0")
	}

	if o.KeyLength == 0 {
		return errors.New("KeyLength must be superior to 0")
	}

	return nil
}
