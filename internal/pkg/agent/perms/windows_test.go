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

func TestFixPermissions_DisablesInheritanceForNestedDirectories(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping test on non-windows platform")
	}

	// Create a nested directory structure to verify inheritance is disabled at all levels
	tmpDir := t.TempDir()
	nestedDir := fmt.Sprintf(`%s\subdir1\subdir2`, tmpDir)
	err := os.MkdirAll(nestedDir, 0755)
	require.NoError(t, err, "failed to create nested directory")

	// Create files in nested directories
	testFile1, err := os.CreateTemp(tmpDir, "testfile")
	require.NoError(t, err, "failed to create test file in root")
	testFile1.Close()
	t.Cleanup(func() { _ = os.Remove(testFile1.Name()) })

	testFile2, err := os.CreateTemp(nestedDir, "testfile")
	require.NoError(t, err, "failed to create test file in nested dir")
	testFile2.Close()
	t.Cleanup(func() { _ = os.Remove(testFile2.Name()) })

	// Fix permissions on the entire tree
	err = FixPermissions(tmpDir)
	require.NoError(t, err, "failed to fix permissions")

	// Verify that all directories have inheritance disabled
	// This is a regression test for the OSQuery extension loading issue
	// where inheritance was only disabled for the top-level directory
	for _, path := range []string{tmpDir, fmt.Sprintf(`%s\subdir1`, tmpDir), nestedDir} {
		t.Run(fmt.Sprintf("verify inheritance disabled for %s", path), func(t *testing.T) {
			secInfo, err := windows.GetNamedSecurityInfo(
				path,
				windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION,
			)
			require.NoError(t, err, "failed to get security info for %s", path)

			dacl, _, err := secInfo.DACL()
			require.NoError(t, err, "failed to get DACL for %s", path)
			require.NotNil(t, dacl, "DACL should not be nil for %s", path)

			// Check that inheritance is disabled by verifying PROTECTED_DACL_SECURITY_INFORMATION flag
			// This is the critical test - inheritance should be disabled for ALL directories
			control, revision, err := secInfo.Control()
			require.NoError(t, err, "failed to get security descriptor control for %s", path)
			_ = revision // unused but needed for API call

			// SE_DACL_PROTECTED flag should be set when inheritance is disabled
			const SE_DACL_PROTECTED = 0x1000
			require.True(t, (control&SE_DACL_PROTECTED) != 0,
				"inheritance should be disabled for %s (DACL should be protected)", path)
		})
	}
}

func TestPermissionFixErrorHandling(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows permission error handling test on non-Windows platform")
	}

	// Test that permission errors are handled gracefully during startup
	// This verifies that the startup code doesn't fail the agent if permissions can't be fixed

	// Test invalid path handling - this should not cause agent startup to fail
	err := FixPermissions(`??INVALID_PATH??`)
	// The function should return an error for invalid paths, but the startup code
	// should log this as a warning and continue. This test verifies that the perms
	// function behaves correctly so the startup code can handle it properly.
	require.Error(t, err, "FixPermissions should return error for invalid path")

	// Test empty path
	err = FixPermissions("")
	require.Error(t, err, "FixPermissions should return error for empty path")

	// Test non-existent path handling (should succeed gracefully due to filterNotFoundErrno)
	err = FixPermissions(`C:\non-existent-path-for-testing`)
	require.NoError(t, err, "FixPermissions should handle non-existent paths gracefully")
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
