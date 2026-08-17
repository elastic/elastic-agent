// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/acl"
)

func TestHasStrictExecPerms_OwnerWriteAllowed(t *testing.T) {
	// A file owned by the current user (no non-privileged group write) should pass.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "exec.exe")
	require.NoError(t, os.WriteFile(path, []byte("dummy"), 0600))

	err := HasStrictExecPerms(path)
	assert.NoError(t, err)
}

func TestHasStrictExecPerms_NonExistentFile(t *testing.T) {
	err := HasStrictExecPerms(`C:\does\not\exist\binary.exe`)
	assert.Error(t, err)
}

func TestHasStrictExecPerms_GroupWriteRejected(t *testing.T) {
	// Grant Everyone write access explicitly; HasStrictExecPerms must reject it.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "tampered.exe")
	require.NoError(t, os.WriteFile(path, []byte("dummy"), 0600))

	everyoneSID, err := windows.StringToSid(EveryoneSID)
	require.NoError(t, err)

	// Grant Everyone FILE_WRITE_DATA on the file.
	err = acl.Apply(path, false, false,
		acl.GrantSid(windows.FILE_WRITE_DATA, everyoneSID),
	)
	require.NoError(t, err)

	err = HasStrictExecPerms(path)
	assert.Error(t, err, "expected error: Everyone has write access")
}

func TestHasStrictExecPerms_CurrentProcessWriteAllowed(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "exec.exe")
	require.NoError(t, os.WriteFile(path, []byte("dummy"), 0600))

	// Use Everyone as the injected current process user so the test exercises
	// the distinction between a trusted writer and the file owner.
	currentUserSID, err := windows.StringToSid(EveryoneSID)
	require.NoError(t, err)
	err = acl.Apply(path, false, false,
		acl.GrantSid(windows.FILE_WRITE_DATA, currentUserSID),
	)
	require.NoError(t, err)

	assert.NoError(t, hasStrictExecPerms(path, currentUserSID))
}

func TestHasStrictExecPermsAndOwnership_DelegatesToHasStrictExecPerms(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "exec.exe")
	require.NoError(t, os.WriteFile(path, []byte("dummy"), 0600))

	// uid is ignored on Windows; result must match HasStrictExecPerms.
	assert.Equal(t, HasStrictExecPerms(path), HasStrictExecPermsAndOwnership(path, 0))
	assert.Equal(t, HasStrictExecPerms(path), HasStrictExecPermsAndOwnership(path, 1000))
}
