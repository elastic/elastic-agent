// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldSkipReplace(t *testing.T) {
	tests := []struct {
		name        string
		original    []byte
		replacement []byte
		expected    bool
	}{
		{
			name:        "original and replacement are the same",
			original:    []byte("fleet:\n  enabled: true\n"),
			replacement: []byte("fleet:\n  enabled: true\n"),
			expected:    true,
		},
		{
			name:        "original and replacement are different",
			original:    []byte("fleet:\n  enabled: true\n"),
			replacement: []byte("fleet:\n  enabled: false\n"),
			expected:    false,
		},
		{
			name:     "original is not a valid yaml",
			original: []byte("fleet: enabled: true\n"),
			expected: false,
		},
		{
			name:        "replacement is not a valid yaml",
			replacement: []byte("fleet: enabled: true\n"),
			expected:    false,
		},
		{
			name:        "original and replacement are different just in comments and spaces",
			original:    []byte("#bla bla bla\nfleet:\n  enabled: true\n"),
			replacement: []byte("fleet:              \n  enabled:          true\n#oh right bla bla bla\n"),
			expected:    true,
		},
		{
			name:        "original contains replacement and more",
			original:    []byte("#bla bla bla\nfleet:\n  enabled: true\nanother: value\nmore:\n  stuff: true\n"),
			replacement: []byte("fleet:\n  enabled: true\n"),
			expected:    true,
		},
		{
			name:        "original contains replacement and more, but in different order",
			original:    []byte("fleet:\n  a_key_that_ruins: sad\n  enabled: true\n"),
			replacement: []byte("fleet:\n  enabled: true\n"),
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, shouldSkipReplace(tt.original, tt.replacement))
		})
	}
}
