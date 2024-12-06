// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGetFileOwnerWindows(t *testing.T) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	require.NoError(t, err)
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	require.NoError(t, err)

	path := t.TempDir()
	fp := filepath.Join(path, "testfile")
	fi, err := os.Create(fp)
	require.NoError(t, err)
	defer fi.Close()

	fo, err := getFileOwner(fp)
	require.NoError(t, err)

	var foSid *windows.SID
	err = windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(fo), &foSid)
	require.NoError(t, err)

	require.True(t, foSid.Equals(tokenUser.User.Sid))
}

func TestIsFileOwnerWindows(t *testing.T) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	require.NoError(t, err)
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	require.NoError(t, err)

	tStr := tokenUser.User.Sid.String()

	eq, err := isFileOwner(tStr, tStr)
	require.NoError(t, err)
	require.True(t, eq, fmt.Sprintf("expected \"true\" received \"%v\"", eq))
}

func TestIsOwnerExecWindows(t *testing.T) {
	path := t.TempDir()
	fp := filepath.Join(path, "testfile")
	fi, err := os.Create(fp)
	require.NoError(t, err)
	defer fi.Close()

	isOwner, err := isOwnerExec(fp)
	require.NoError(t, err)

	require.True(t, isOwner, fmt.Sprintf("expected isOwnerExec to return \"true\", received \"%v\"", isOwner))
}
