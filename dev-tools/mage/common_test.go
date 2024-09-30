// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	var tests = []struct {
		Version             string
		Major, Minor, Patch int
	}{
		{"v1.2.3", 1, 2, 3},
		{"1.2.3", 1, 2, 3},
		{"1.2.3-SNAPSHOT", 1, 2, 3},
		{"1.2.3rc1", 1, 2, 3},
		{"1.2", 1, 2, 0},
		{"7.10.0", 7, 10, 0},
		{"10.01.22", 10, 1, 22},
	}

	for _, tc := range tests {
		major, minor, patch, err := ParseVersion(tc.Version)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, tc.Major, major)
		assert.Equal(t, tc.Minor, minor)
		assert.Equal(t, tc.Patch, patch)
	}
}
