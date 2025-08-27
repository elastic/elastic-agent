// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/utils"
)

type testCase struct {
	setup   func(t *testing.T) string
	wantErr bool
}

func TestGetFileOwnerFromPath(t *testing.T) {
	testCases := map[string]testCase{
		"returns current owner for regular file": {
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				fp := filepath.Join(dir, "tmpfile")
				f, err := os.Create(fp)
				require.NoError(t, err, "failed to create temp file")
				require.NoError(t, f.Close(), "failed to close temp file")
				return fp
			},
		},
		"returns current owner for directory": {
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
		},
		"returns error for nonexistent path": {
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "does", "not", "exist")
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			path := tc.setup(t)
			owner, err := getFileOwnerFromPath(path)
			if tc.wantErr {
				require.Error(t, err, "expected error for path %q", path)
				return
			}
			require.NoError(t, err, "unexpected error for path %q", path)

			cur, err := utils.CurrentFileOwner()
			require.NoError(t, err, "failed to get current file owner")
			require.Equal(t, cur.UID, owner.UID, "uid mismatch for %q", path)
			require.Equal(t, cur.GID, owner.GID, "gid mismatch for %q", path)
		})
	}
}
