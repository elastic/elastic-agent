// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package perms

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/stretchr/testify/require"
)

func TestFixPermissions(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping test on non-windows platform")
	}

	// Create a temporary file
	tmpDir := t.TempDir()

	// arbitrary number of files
	for i := 0; i < 5; i++ {
		tmpFile, err := os.CreateTemp(tmpDir, "testfile")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Remove(tmpFile.Name()) // Ensure cleanup
		})

		// Close file before changing permissions
		err = tmpFile.Close()
		require.NoError(t, err, "failed to close file")
	}

	err := FixPermissions(tmpDir)
	require.NoError(t, err, "failed to fix permissions")
}

func Test_applyPermissions(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping test on non-windows platform")
	}

	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name()) // Ensure cleanup
	}()

	// Close file before changing permissions
	err = tmpFile.Close()
	require.NoError(t, err, "failed to close file")

	for _, tc := range []struct {
		name        string
		filePath    string
		expectedErr error
	}{
		{
			name:        "should succeed",
			filePath:    tmpFile.Name(),
			expectedErr: nil,
		},
		{
			name:        "non existing file, no error",
			filePath:    fmt.Sprintf(`%s\non-existing`, tmpDir),
			expectedErr: nil,
		},
		{
			name:        "non existing path, no error",
			filePath:    `C:\non-existing\non-existing`,
			expectedErr: nil,
		},
		{
			name:        "invalid path",
			filePath:    `??INVALID_PATH??`,
			expectedErr: windows.ERROR_INVALID_NAME,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := applyPermissions(tc.filePath, true, false, nil, nil)
			if tc.expectedErr != nil {
				require.Error(t, err, "expected error, got nil")
				require.ErrorIs(t, err, tc.expectedErr, "errors do not match")
			} else {
				require.NoError(t, err, "expected no error, got %v", err)
			}
		})
	}
}
