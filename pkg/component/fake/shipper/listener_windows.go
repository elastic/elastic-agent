// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package main

import (
	"fmt"
	"net"
	"os/user"

	"github.com/elastic/elastic-agent-libs/api/npipe"
)

// createListener creates a named pipe listener on Windows
func createListener(path string) (net.Listener, error) {
	sd, err := securityDescriptor()
	if err != nil {
		return nil, err
	}
	return npipe.NewListener(path, sd)
}

func securityDescriptor() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}
	// Named pipe security and access rights.
	// We create the pipe and the specific users should only be able to write to it.
	// See docs: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
	// String definition: https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
	// Give generic read/write access to the specified user.
	descriptor := "D:P(A;;GA;;;" + u.Uid + ")"
	return descriptor, nil
}
