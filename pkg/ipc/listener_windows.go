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

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/api/npipe"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
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

	isAdmin, err := utils.HasRoot()
	if err != nil {
		// do not fail, agent would end up in a loop, continue with limited permissions
		log.Warnf("failed to detect Administrator: %w", err)
		isAdmin = false // just in-case to ensure that in error case that its always false
	}
	// SYSTEM/Administrators can always talk over the pipe, even when not running as privileged
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	descriptor += "(A;;GA;;;" + utils.AdministratorSID + ")"
	if !isAdmin && paths.RunningInstalled() {
		// Windows doesn't provide a way to set the executing group when being executed as a service,
		// but a group needs to be added to the named pipe in unprivileged mode to allow users in the group
		// to ability to communicate with the named pipe.
		//
		// During installation a group is set as the owner of the files which can be used here to determine
		// the group that should be added to the named pipe.
		gid, err := pathGID(paths.Top())
		if err != nil {
			// do not fail, agent would end up in a loop, continue with limited permissions
			log.Warnf("failed to detect group: %w", err)
		} else {
			descriptor += "(A;;GA;;;" + gid + ")"
		}
	}

	return descriptor, nil
}

func pathGID(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.GROUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("call to GetNamedSecurityInfo at %s failed: %w", path, err)
	}

	group, _, err := sd.Group()
	if err != nil {
		return "", fmt.Errorf("failed to determine group using GetNamedSecurityInfo at %s: %w", path, err)
	}
	return group.String(), nil
}
