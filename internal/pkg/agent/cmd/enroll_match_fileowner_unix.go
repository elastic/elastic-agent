// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

var UserOwnerMismatchError = errors.New("the command is executed as root but the program files are not owned by the root user. execute the command as the user that owns the program files")

func getFileOwner(filePath string) (string, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %w", err)
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("failed to get system specific file info: %w", err)
	}
	return strconv.FormatInt(int64(stat.Uid), 10), nil
}

func getCurrentUser() (string, error) {
	return strconv.Itoa(os.Geteuid()), nil
}

func isFileOwner(curUser string, fileOwner string) (bool, error) {
	return curUser == fileOwner, nil
}

func isOwnerExec() (bool, error) {
	binPath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("failed to get binpath: %w", err)
	}

	owner, err := getFileOwner(binPath)
	if err != nil {
		return false, fmt.Errorf("failed to get file owner: %w", err)
	}

	curUser, err := getCurrentUser()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}

	isOwner, err := isFileOwner(curUser, owner)
	if err != nil {
		return false, fmt.Errorf("error while checking if current user is the file owner: %w", err)
	}

	if !isOwner {
		return false, nil
	}

	return true, nil
}
