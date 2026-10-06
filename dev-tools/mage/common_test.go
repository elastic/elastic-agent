// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindFilesRecursive(t *testing.T) {
	dir := t.TempDir()

	mkfile := func(rel string) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, nil, 0o644))
	}

	// Regular files the match function should find.
	mkfile("a.go")
	mkfile("sub/b.go")
	mkfile("sub/c.txt")

	// The repo's own .git directory — files inside must not be returned.
	mkfile(".git/HEAD")
	mkfile(".git/config")

	// A git submodule: .git is a file, the directory should be skipped entirely.
	mkfile("submodule/.git") // file, not dir
	mkfile("submodule/d.go")

	// A git worktree: same shape as a submodule from the walker's perspective.
	mkfile("worktrees/feat/.git") // file, not dir
	mkfile("worktrees/feat/e.go")

	t.Chdir(dir)

	t.Run("returns only files matched by the predicate", func(t *testing.T) {
		files, err := FindFilesRecursive(func(path string, _ os.FileInfo) bool {
			return filepath.Ext(path) == ".go"
		})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"a.go", filepath.FromSlash("sub/b.go")}, files)
	})

	t.Run("does not descend into the .git directory", func(t *testing.T) {
		files, err := FindFilesRecursive(func(path string, _ os.FileInfo) bool {
			return strings.HasPrefix(path, ".git/")
		})
		require.NoError(t, err)
		assert.Empty(t, files)
	})

	t.Run("does not descend into directories that contain a .git entry", func(t *testing.T) {
		files, err := FindFilesRecursive(func(_ string, _ os.FileInfo) bool { return true })
		require.NoError(t, err)
		for _, f := range files {
			slashF := filepath.ToSlash(f)
			assert.False(t, strings.HasPrefix(slashF, "submodule/"), "walked into submodule: %s", f)
			assert.False(t, strings.HasPrefix(slashF, "worktrees/feat/"), "walked into worktree: %s", f)
		}
	})
}

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
