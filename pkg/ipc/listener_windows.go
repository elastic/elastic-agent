// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package ipc

import (
	"fmt"
	"net"
	"os/user"
	"strings"

	"github.com/elastic/elastic-agent-libs/api/npipe"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const schemeNpipePrefix = "npipe://"

func IsLocal(address string) bool {
	return strings.HasPrefix(address, schemeNpipePrefix)
}

// CreateListener creates net listener from address string
// Shared for control and beats comms sockets
func CreateListener(log *logger.Logger, address string) (net.Listener, error) {
	sd, err := securityDescriptor(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create security descriptor: %w", err)
	}
	lis, err := npipe.NewListener(npipe.TransformString(address), sd)
	if err != nil {
		return nil, fmt.Errorf("failed to create npipe listener: %w", err)
	}
	return lis, nil
}

func CleanupListener(log *logger.Logger, address string) {
	// nothing to do on windows
}

func securityDescriptor(log *logger.Logger) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	descriptor := "D:P(A;;GA;;;" + u.Uid + ")"

	if isAdmin, err := utils.HasRoot(); err != nil {
		// do not fail, agent would end up in a loop, continue with limited permissions
		log.Warnf("failed to detect admin: %w", err)
	} else if isAdmin {
		// running as SYSTEM, include Administrators group so Administrators can talk over
		// the named pipe to the running Elastic Agent system process
		// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
		descriptor += "(A;;GA;;;" + utils.AdministratorSID + ")"
	}

	return descriptor, nil
}
