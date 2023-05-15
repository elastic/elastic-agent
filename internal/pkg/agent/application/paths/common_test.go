// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package paths

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

func validTestPath() string {
	validPath := filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit()))
	if runtime.GOOS == darwin {
		validPath = filepath.Join(validPath, "elastic-agent.app", "Contents", "MacOS")
	}
	return validPath
}

func TestIsInsideData(t *testing.T) {
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
			exePath: validTestPath(),
			res:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := isInsideData(tc.exePath)
			diff := cmp.Diff(tc.res, res)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestExecDir(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "Library", "Elastic", "Agent")
	tests := []struct {
		name    string
		execDir string
		resDir  string
	}{
		{
			name: "empty",
		},
		{
			name:    "non-data path",
			execDir: "data/elastic-agent",
			resDir:  "data/elastic-agent",
		},
		{
			name:    "valid",
			execDir: validTestPath(),
			resDir:  ".",
		},
		{
			name:    "valid abs",
			execDir: filepath.Join(base, validTestPath()),
			resDir:  base,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resDir := ExecDir(tc.execDir)
			diff := cmp.Diff(tc.resDir, resDir)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
