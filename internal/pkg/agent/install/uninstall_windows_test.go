// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemovePath(t *testing.T) {
	var (
		pkgName    = "testblocking"
		binaryName = pkgName + ".exe"
	)

	// Create a temporary directory that we can safely remove. The directory is created as a new
	// sub-directory. This avoids having Microsoft Defender quarantine the file if it is exec'd from
	// the default temporary directory.
	destDir, err := os.MkdirTemp(pkgName, t.Name())
	require.NoError(t, err)

	// Copy the test executable to the new temporary directory.
	destpath, err := filepath.Abs(filepath.Join(destDir, binaryName))
	require.NoErrorf(t, err, "failed dest abs %s + %s", destDir, binaryName)

	srcPath, err := filepath.Abs(filepath.Join(pkgName, binaryName))
	require.NoErrorf(t, err, "failed src abs %s + %s", pkgName, binaryName)

	err = copy.Copy(srcPath, destpath, copy.Options{Sync: true})
	require.NoError(t, err)

	// Execute the test executable asynchronously.
	cmd := exec.Command(destpath)
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Ensure the directory containing the executable can be removed.
	err = RemovePath(destDir)
	assert.NoError(t, err)
	_, err = os.Stat(destDir)
	assert.ErrorIsf(t, err, fs.ErrNotExist, "path %q still exists after removal", destDir)
}
