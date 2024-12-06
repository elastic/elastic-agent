// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

var UserOwnerMismatchError = errors.New("the command is executed as root but the program files are not owned by the root user.")

func getFileOwner(filePath string) (string, error) {
	// Get security information of the file
	sd, err := windows.GetNamedSecurityInfo(
		filePath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get security info: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", fmt.Errorf("failed to get security descriptor owner: %w", err)
	}

	return owner.String(), nil
}

// Helper to get the current user's SID
func getCurrentUser() (string, error) {
	// Get the token for the current process
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	// Get the token use
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("failed to get token user: %w", err)
	}

	return tokenUser.User.Sid.String(), nil
}

func isFileOwner(curUser string, fileOwner string) (bool, error) {
	var cSid *windows.SID
	err := windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(curUser), &cSid)
	if err != nil {
		return false, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	var fSid *windows.SID
	err = windows.ConvertStringSidToSid(windows.StringToUTF16Ptr(fileOwner), &fSid)
	if err != nil {
		return false, fmt.Errorf("failed to convert SID string to SID: %w", err)
	}

	isEqual := fSid.Equals(cSid)

	return isEqual, nil
}

func isOwnerExec(filePath string) (bool, error) {
	fileOwner, err := getFileOwner(filePath)
	if err != nil {
		return false, fmt.Errorf("ran into an error while getting file owner: %w", err)
	}

	user, err := getCurrentUser()
	if err != nil {
		return false, fmt.Errorf("ran into an error while retrieving current user: %w", err)
	}

	return isFileOwner(user, fileOwner)
}
