// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsInsideData(t *testing.T) {

	validExePath := "data/elastic-agent-unknow" // "unknown" the private default value, trimmed for hash value length

	if runtime.GOOS == darwin {
		validExePath = filepath.Join(validExePath, "elastic-agent.app", "Contents", "MacOS")
	}

	tests := []struct {
		name    string
		exePath string
		res     bool
	}{
		{
			name: "empty",
		},
		{
			name:    "invalid",
			exePath: "data/elastic-agent",
		},
		{
			name:    "valid",
			exePath: validExePath,
			res:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := IsInsideData(tc.exePath)
			diff := cmp.Diff(tc.res, res)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
