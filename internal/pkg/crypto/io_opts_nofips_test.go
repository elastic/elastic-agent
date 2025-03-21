// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Option_Validate(t *testing.T) {
	t.Run("default has no errors", func(t *testing.T) {
		err := DefaultOptions.Validate()
		assert.NoError(t, err)
	})

	tests := []struct {
		name   string
		option *Option
	}{{
		name: "IVLength is 0",
		option: &Option{
			IVLength:        0,
			SaltLength:      1,
			IterationsCount: 1,
			KeyLength:       1,
		},
	}, {
		name: "SaltLength is 0",
		option: &Option{
			IVLength:        1,
			SaltLength:      0,
			IterationsCount: 1,
			KeyLength:       1,
		},
	}, {
		name: "IterationsCount is 0",
		option: &Option{
			IVLength:        1,
			SaltLength:      1,
			IterationsCount: 0,
			KeyLength:       1,
		},
	}, {
		name: "KeyLength is 0",
		option: &Option{
			IVLength:        1,
			SaltLength:      1,
			IterationsCount: 1,
			KeyLength:       0,
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.option.Validate()
			assert.Error(t, err, "expected validation to fail with error")
		})
	}
}
