// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package paths

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/version"
)

func validTestPath(useVersionInPath bool) string {
	validPath := filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit()))
	if useVersionInPath {
		validPath = filepath.Join("data", fmt.Sprintf("elastic-agent-%s-%s", version.GetAgentPackageVersion(), release.ShortCommit()))
	}
	if runtime.GOOS == darwin {
		validPath = filepath.Join(validPath, "elastic-agent.app", "Contents", "MacOS")
	}
	return validPath
}

func TestIsInsideData(t *testing.T) {
	tests := []struct {
		setup   func(*testing.T)
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
			exePath: validTestPath(false),
			res:     true,
		},
		{
			name:    "valid with version in path",
			exePath: validTestPath(true),
			res:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
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
			execDir: validTestPath(false),
			resDir:  ".",
		},
		{
			name:    "valid abs",
			execDir: filepath.Join(base, validTestPath(false)),
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

func TestPathSplitUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix tests on Windows")
	}
	tests := map[string]struct {
		path string
		want []string
	}{
		"empty string": {path: "", want: []string{}},
		"just file":    {path: "test.txt", want: []string{"test.txt"}},
		"just dir":     {path: "/", want: []string{}},
		"top dir":      {path: "/test.txt", want: []string{"test.txt"}},
		"simple":       {path: "/a/b", want: []string{"a", "b"}},
		"long":         {path: "/a/b c/d-e/f_g", want: []string{"a", "b c", "d-e", "f_g"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := pathSplit(tc.path)
			if !cmp.Equal(tc.want, got) {
				t.Fatalf("not equal got: %v, want: %v", got, tc.want)
			}
		})
	}
}

func TestPathSplitWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows tests on non Windows")
	}
	tests := map[string]struct {
		path string
		want []string
	}{
		"empty string": {path: "", want: []string{}},
		"just file":    {path: "test.txt", want: []string{"test.txt"}},
		"just dir":     {path: "C:\\", want: []string{}},
		"top dir":      {path: "C:\\test.txt", want: []string{"test.txt"}},
		"simple":       {path: "C:\\a\\b", want: []string{"a", "b"}},
		"long":         {path: "C:\\a\\b c\\d-e\\f_g", want: []string{"a", "b c", "d-e", "f_g"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := pathSplit(tc.path)
			if !cmp.Equal(tc.want, got) {
				t.Fatalf("not equal got: %v, want: %v", got, tc.want)
			}
		})
	}
}
