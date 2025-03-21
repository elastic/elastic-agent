// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Option_ValidateFIPS(t *testing.T) {
	t.Run("default has no errors", func(t *testing.T) {
		err := DefaultOptions.Validate()
		assert.NoError(t, err)
	})

	tests := []struct {
		name   string
		option *Option
	}{{
		name: "IVLength is low",
		option: &Option{
			IVLength:        10,
			SaltLength:      20,
			IterationsCount: 10000,
			KeyLength:       20,
		},
	}, {
		name: "SaltLength is low",
		option: &Option{
			IVLength:        20,
			SaltLength:      10,
			IterationsCount: 10000,
			KeyLength:       20,
		},
	}, {
		name: "IterationsCount is low",
		option: &Option{
			IVLength:        20,
			SaltLength:      20,
			IterationsCount: 100,
			KeyLength:       20,
		},
	}, {
		name: "KeyLength is low",
		option: &Option{
			IVLength:        20,
			SaltLength:      20,
			IterationsCount: 10000,
			KeyLength:       10,
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.option.Validate()
			assert.Error(t, err, "expected validation to fail with error")
		})
	}
}
