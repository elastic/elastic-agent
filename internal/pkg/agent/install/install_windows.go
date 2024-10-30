// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/elastic/elastic-agent/version"
)

// postInstall performs post installation for Windows systems.
func postInstall(topPath string) error {
	// delete the top-level elastic-agent.exe
	binary := filepath.Join(topPath, paths.BinaryName)
	err := os.Remove(binary)
	if err != nil {
		// do not handle does not exist, it should have existed
		return err
	}

	// since we removed the top-level elastic-agent.exe we can get
	// rid of the package version file (it was there only in case
	// the top .exe was called with a `version` subcommand )
	err = os.Remove(filepath.Join(topPath, version.PackageVersionFileName))
	if err != nil {
		// do not handle does not exist, it should have existed
		return err
	}

	// create top-level symlink to nested binary
	realBinary := paths.BinaryPath(paths.VersionedHome(topPath), paths.BinaryName)
	err = os.Symlink(realBinary, binary)
	if err != nil {
		return err
	}

	return nil
}

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	return perms.FixPermissions(markerFilePath, perms.WithOwnership(ownership))
}

// withServiceOptions just sets the user/group for the service.
func withServiceOptions(username string, groupName string, password string) ([]serviceOpt, error) {
	if username == "" {
		// not installed with --unprivileged; nothing to do
		return []serviceOpt{}, nil
	}

	if password != "" {
		// existing user
		return []serviceOpt{withUserGroup(username, groupName), withPassword(password)}, nil
	}

	// service requires a password to launch as the user
	// this sets it to a random password that is only known by the service
	password, err := RandomPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random password: %w", err)
	}
	err = SetUserPassword(username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to set user %s password for service: %w", username, err)
	}

	// username must be prefixed with `.\` so the service references the local systems users
	username = fmt.Sprintf(`.\%s`, username)
	return []serviceOpt{withUserGroup(username, groupName), withPassword(password)}, nil
}

// serviceConfigure sets the security descriptor for the service
//
// gives user the ability to control the service, needed when installed with --unprivileged or
// ReExec is not possible on Windows.
func serviceConfigure(ownership utils.FileOwner) error {
	// Modify registry to allow logging to eventlog as "Elastic Agent".
	err := eventlog.InstallAsEventCreate(paths.ServiceName(), eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && !strings.Contains(err.Error(), "registry key already exists") {
		return fmt.Errorf("unable to create registry key for logging: %w", err)
	}
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects
	sddl := "D:(A;;GA;;;SY)" + // SDDL_LOCAL_SYSTEM -> SDDL_GENERIC_ALL
		"(A;;GA;;;BA)" + // SDDL_BUILTIN_ADMINISTRATORS -> SDDL_GENERIC_ALL
		"(A;;GR;;;WD)" + // SDDL_EVERYONE -> SDDL_GENERIC_READ
		"(A;;GRGX;;;NS)" // SDDL_NETWORK_SERVICE -> SDDL_GENERIC_READ|SDDL_GENERIC_EXECUTE
	if ownership.UID != "" {
		sddl += fmt.Sprintf("(A;;GA;;;%s)", ownership.UID) // Ownership UID -> SDDL_GENERIC_ALL
	}
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("failed to build security descriptor from SSDL: %w", err)
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return fmt.Errorf("failed to get DACL from security descriptor: %w", err)
	}
	err = windows.SetNamedSecurityInfo(paths.ServiceName(), windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("failed to set DACL for service(%s): %w", paths.ServiceName(), err)
	}
	return nil
}
