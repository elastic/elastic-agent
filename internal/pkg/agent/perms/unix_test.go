// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package perms

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/stretchr/testify/require"
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

func Test_isSameUser_MatchesCurrentOwner(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0600))

	info, err := os.Lstat(filePath)
	require.NoError(t, err)

	owner, err := utils.CurrentFileOwner()
	require.NoError(t, err)

	same, err := isSameUser(info, owner)
	require.NoError(t, err)
	require.True(t, same)
}

func Test_isSameUser_MismatchReturnsFalse(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0600))

	info, err := os.Lstat(filePath)
	require.NoError(t, err)

	owner, err := utils.CurrentFileOwner()
	require.NoError(t, err)
	owner.UID++

	same, err := isSameUser(info, owner)
	require.NoError(t, err)
	require.False(t, same)
}

func Test_isSameUser_UsesLstatForSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target")
	require.NoError(t, os.WriteFile(targetPath, []byte("hello"), 0600))

	linkPath := filepath.Join(tmpDir, "link")
	require.NoError(t, os.Symlink(targetPath, linkPath))

	info, err := os.Lstat(linkPath)
	require.NoError(t, err)

	owner, err := utils.CurrentFileOwner()
	require.NoError(t, err)

	same, err := isSameUser(info, owner)
	require.NoError(t, err)
	require.True(t, same)
}

func Test_isSameUser_ErrorsWhenNoStatT(t *testing.T) {
	owner, err := utils.CurrentFileOwner()
	require.NoError(t, err)

	info := fileInfoWithoutStatT{name: "not-a-real-file"}
	same, err := isSameUser(info, owner)
	require.Error(t, err)
	require.False(t, same)
}

type fileInfoWithoutStatT struct {
	name string
}

func (f fileInfoWithoutStatT) Name() string       { return f.name }
func (f fileInfoWithoutStatT) Size() int64        { return 0 }
func (f fileInfoWithoutStatT) Mode() fs.FileMode  { return 0 }
func (f fileInfoWithoutStatT) ModTime() time.Time { return time.Time{} }
func (f fileInfoWithoutStatT) IsDir() bool        { return false }
func (f fileInfoWithoutStatT) Sys() any           { return nil }

