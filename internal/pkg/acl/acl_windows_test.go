// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package acl

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/stretchr/testify/require"
)

func TestChmod(t *testing.T) {
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
			name:        "non existing file",
			filePath:    fmt.Sprintf(`%s\non-existing`, tmpDir),
			expectedErr: windows.ERROR_FILE_NOT_FOUND,
		},
		{
			name:        "non existing path",
			filePath:    `C:\non-existing\non-existing`,
			expectedErr: windows.ERROR_PATH_NOT_FOUND,
		},
		{
			name:        "invalid path",
			filePath:    `??INVALID_PATH??`,
			expectedErr: windows.ERROR_INVALID_NAME,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Chmod(tc.filePath, 0400)
			if tc.expectedErr != nil {
				require.Error(t, err, "expected error, got nil")
				require.ErrorIs(t, err, tc.expectedErr, "errors do not match")
			} else {
				require.NoError(t, err, "expected no error, got %v", err)
			}
		})
	}
}

func TestSetEntriesInAcl_Error(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping test on non-windows platform")
	}

	var newAcl windows.Handle

	// Invalid ACL handle (forces failure)
	invalidOldAcl := windows.Handle(0xFFFFFFFF)
	err := SetEntriesInAcl(nil, invalidOldAcl, &newAcl)
	if err == nil {
		t.Fatalf("Expected an error, but got nil")
	}

	require.Error(t, err, "expected error, got nil")
	// ret=87 ERROR_INVALID_PARAMETER
	require.ErrorIs(t, err, windows.ERROR_INVALID_PARAMETER, "errors do not match")
}

func TestGetNamedSecurityInfo_Error(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping test on non-windows platform")
	}

	// Invalid parameters
	invalidObjectName := "??INVALID_PATH??" // Invalid file path
	invalidObjectType := int32(-1)          // Invalid object type
	invalidSecInfo := uint32(0xFFFFFFFF)    // Invalid security information flags

	var owner, group *windows.SID
	var dacl, sacl, secDesc windows.Handle

	// Call function with invalid parameters
	err := GetNamedSecurityInfo(invalidObjectName, invalidObjectType, invalidSecInfo, &owner, &group, &dacl, &sacl, &secDesc)
	if err == nil {
		t.Fatalf("Expected an error, but got nil")
	}

	require.Error(t, err, "expected error, got nil")
	// ret=87 ERROR_INVALID_PARAMETER
	require.ErrorIs(t, err, windows.ERROR_INVALID_PARAMETER, "errors do not match")
}
