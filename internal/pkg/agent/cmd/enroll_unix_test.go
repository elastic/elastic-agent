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
)

type testCase struct {
	setup   func(t *testing.T) string
	wantErr bool
}

func TestGetFileOwnerFromPath(t *testing.T) {
	baseDir := t.TempDir()
	uid := os.Geteuid()
	gid := os.Getegid()

	testCases := map[string]testCase{
		"returns current owner for regular file": {
			setup: func(t *testing.T) string {
				fp := filepath.Join(baseDir, "tmpfile")
				f, err := os.Create(fp)
				require.NoError(t, err, "failed to create temp file")
				require.NoError(t, f.Close(), "failed to close temp file")

				// make sure the file is owned by the current user and group
				err = os.Chown(fp, uid, gid)
				require.NoError(t, err, "failed to chown temp file")

				return fp
			},
		},
		"returns current owner for directory": {
			setup: func(t *testing.T) string {
				dirPath := filepath.Join(baseDir, "tmpdir")
				err := os.Mkdir(dirPath, 0755)
				require.NoError(t, err, "failed to create temp dir")

				// make sure the dir is owned by the current user and group
				err = os.Chown(dirPath, uid, gid)
				require.NoError(t, err, "failed to chown temp dir")

				return dirPath
			},
		},
		"returns error for nonexistent path": {
			setup: func(t *testing.T) string {
				return filepath.Join(baseDir, "mockFile")
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			path := tc.setup(t)
			owner, err := getOwnerFromPath(path)
			if tc.wantErr {
				require.Error(t, err, "expected error for path %q", path)
				require.Empty(t, owner, "expected empty owner for path %q", path)
				return
			}
			require.NoError(t, err, "unexpected error for path %q", path)

			require.Equal(t, uid, owner.UID, "uid mismatch for %q", path)
			require.Equal(t, gid, owner.GID, "gid mismatch for %q", path)
		})
	}
}
