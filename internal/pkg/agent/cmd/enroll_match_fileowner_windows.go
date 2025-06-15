// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import "github.com/elastic/elastic-agent/internal/pkg/agent/errors"

var UserOwnerMismatchError = errors.New("the command is executed as root but the program files are not owned by the root user. execute the command as the user that owns the program files")

func isOwnerExec(path string) (bool, error) {
	// No-op for Windows: always allow
	return true, nil
}
