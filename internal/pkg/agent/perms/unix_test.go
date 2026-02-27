// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package perms

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestFixPermissions_MasksWorldPermissions(t *testing.T) {
	tmpDir := t.TempDir()

	nestedDir := filepath.Join(tmpDir, "nested")
	require.NoError(t, os.MkdirAll(nestedDir, 0777))

	filePath := filepath.Join(nestedDir, "file")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0666))

	// Make both dir and file world-accessible so the mask has something to change.
	require.NoError(t, os.Chmod(nestedDir, 0777))
	require.NoError(t, os.Chmod(filePath, 0777))

	err := FixPermissions(tmpDir)
	require.NoError(t, err)

	dirInfo, err := os.Stat(nestedDir)
	require.NoError(t, err)
	fileInfo, err := os.Stat(filePath)
	require.NoError(t, err)

	// Default mask is 0770; ensure "other" bits are removed.
	require.Equal(t, os.FileMode(0), dirInfo.Mode().Perm()&0007)
	require.Equal(t, os.FileMode(0), fileInfo.Mode().Perm()&0007)
}

func TestFixPermissions_NonExistentRootIsIgnored(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist")

	err := FixPermissions(nonExistent)
	require.NoError(t, err)
}

func TestIsMaskStripped(t *testing.T) {
	perms := []os.FileMode{0777, 0755, 0770, 0700}
	for _, perm := range perms {
		fileInfo := testFileInfo{mode: perm}
		require.Equal(t, perm&0007 == 0, maskIsStripped(fileInfo, 0007), "expected mask to be stripped for permissions %o", perm)
	}

}

func Test_isSameUser_MatchesCurrentOwner(t *testing.T) {
	testCases := []struct {
		name     string
		info     testFileInfo
		owner    utils.FileOwner
		expected bool
	}{
		{
			name:     "matching UID and GID",
			info:     testFileInfo{sys: &syscall.Stat_t{Uid: 1000, Gid: 1000}},
			owner:    utils.FileOwner{UID: 1000, GID: 1000},
			expected: true,
		},
		{
			name:     "non-matching UID and GID",
			info:     testFileInfo{sys: &syscall.Stat_t{Uid: 1000, Gid: 1000}},
			owner:    utils.FileOwner{UID: 2000, GID: 2000},
			expected: false,
		},
		{
			name:     "non-matching UID",
			info:     testFileInfo{sys: &syscall.Stat_t{Uid: 1000, Gid: 1000}},
			owner:    utils.FileOwner{UID: 2000, GID: 1000},
			expected: false,
		},
		{
			name:     "non-matching GID",
			info:     testFileInfo{sys: &syscall.Stat_t{Uid: 1000, Gid: 1000}},
			owner:    utils.FileOwner{UID: 1000, GID: 2000},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			same, err := isSameUser(tc.info, tc.owner)
			require.NoError(t, err)
			require.Equal(t, tc.expected, same, "expected isSameUser to return %v when UID %d:%d matches %d:%d", tc.expected, tc.owner.UID, tc.owner.GID, tc.info.Sys().(*syscall.Stat_t).Uid, tc.info.Sys().(*syscall.Stat_t).Gid)
		})
	}
}

func Test_isSameUser_ErrorsWhenNoStatT(t *testing.T) {
	owner, err := utils.CurrentFileOwner()
	require.NoError(t, err)

	info := testFileInfo{name: "not-a-real-file"}
	same, err := isSameUser(info, owner)
	require.Error(t, err)
	require.False(t, same)
}

type testFileInfo struct {
	name string
	mode fs.FileMode
	sys  *syscall.Stat_t
}

func (f testFileInfo) Name() string       { return f.name }
func (f testFileInfo) Size() int64        { return 0 }
func (f testFileInfo) Mode() fs.FileMode  { return f.mode }
func (f testFileInfo) ModTime() time.Time { return time.Time{} }
func (f testFileInfo) IsDir() bool        { return false }
func (f testFileInfo) Sys() any           { return f.sys }
