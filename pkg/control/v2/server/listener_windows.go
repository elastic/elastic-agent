// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package server

import (
	"net"
	"os/user"
	"strings"

	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/elastic/elastic-agent/pkg/control"

	"github.com/pkg/errors"

	"github.com/elastic/elastic-agent-libs/api/npipe"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// createListener creates a named pipe listener on Windows
func createListener(log *logger.Logger) (net.Listener, error) {
	sd, err := securityDescriptor(log)
	if err != nil {
		return nil, err
	}
	return npipe.NewListener(control.Address(), sd)
}

func cleanupListener(_ *logger.Logger) {
	// nothing to do on windows
}

func securityDescriptor(log *logger.Logger) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", errors.Wrap(err, "failed to get current user")
	}
	// Named pipe security and access rights.
	// We create the pipe and the specific users should only be able to write to it.
	// See docs: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
	// String definition: https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
	// Give generic read/write access to the specified user.
	descriptor := "D:P(A;;GA;;;" + u.Uid + ")"

	if isAdmin, err := isWindowsAdmin(u); err != nil {
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

func isWindowsAdmin(u *user.User) (bool, error) {
	if u.Username == "NT AUTHORITY\\SYSTEM" {
		return true, nil
	}

	if equalsSystemGroup(u.Uid) || equalsSystemGroup(u.Gid) {
		return true, nil
	}

	groups, err := u.GroupIds()
	if err != nil {
		return false, errors.Wrap(err, "failed to get current user groups")
	}

	for _, groupSid := range groups {
		if equalsSystemGroup(groupSid) {
			return true, nil
		}
	}

	return false, nil
}

func equalsSystemGroup(s string) bool {
	return strings.EqualFold(s, utils.SystemSID) || strings.EqualFold(s, utils.AdministratorSID)
}
