// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_createFile(t *testing.T) {
	dir := t.TempDir()
	existingFile := "existingfile.zip"
	f, err := os.Create(path.Join(dir, "existingFile"))
	require.NoErrorf(t, err, "could not create file %q", path.Join(dir, "existingFile"))
	err = f.Close()
	require.NoError(t, err, "could not close file")

	testCases := []struct {
		name     string
		filePath string
	}{
		{
			name:     "ExistingFile",
			filePath: path.Join(dir, existingFile),
		},
		{
			name:     "NewFile",
			filePath: path.Join(dir, "newfile.zip"),
		},
		{
			name:     "NonexistentFolders",
			filePath: path.Join(dir, "nonexistent", "folders", "file.zip"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := createFile(tc.filePath)
			require.NoError(t, err, "failed creating diagnostics file %q",
				tc.filePath)
			defer func() {
				file.Close()
			}()
		})
	}
}
