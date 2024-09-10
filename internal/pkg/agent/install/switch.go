// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"fmt"

	"github.com/kardianos/service"
	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// SwitchExecutingMode switches the executing mode of the installed Elastic Agent.
//
// When username and groupName are blank then it switched back to root/Administrator and when a username/groupName is
// provided then it switched to running with that username and groupName.
func SwitchExecutingMode(topPath string, pt *progressbar.ProgressBar, username string, groupName string) error {
	// ensure service is stopped
	status, err := EnsureStoppedService(topPath, pt)
	if err != nil {
		// context for the error already provided in the EnsureStoppedService function
		return err
	}

	// ensure that upon exit of this function that the service is always placed back to running, in the case
	// that it was running when the command was executed
	defer func() {
		if err != nil && status == service.StatusRunning {
			_ = StartService(topPath)
		}
	}()

	// ensure user/group are created
	var ownership utils.FileOwner
	if username != "" && groupName != "" {
		ownership, err = EnsureUserAndGroup(username, groupName, pt)
		if err != nil {
			// context for the error already provided in the EnsureUserAndGroup function
			return err
		}
	}

	// **start critical section**
	// after this point changes will be made that can leave the installed Elastic Agent broken if they do not
	// complete successfully

	// perform platform specific work
	err = switchPlatformMode(pt, ownership)

	// fix all permissions to use the new ownership
	pt.Describe("Adjusting permissions")
	err = perms.FixPermissions(topPath, perms.WithOwnership(ownership))
	if err != nil {
		return fmt.Errorf("failed to perform permission changes on path %s: %w", topPath, err)
	}
	if paths.ShellWrapperPath() != "" {
		err = perms.FixPermissions(paths.ShellWrapperPath(), perms.WithOwnership(ownership))
		if err != nil {
			return fmt.Errorf("failed to perform permission changes on path %s: %w", paths.ShellWrapperPath(), err)
		}
	}

	// the service has to be uninstalled
	pt.Describe("Removing service")
	// error is ignored because it's possible that its already uninstalled
	//
	// this can happen if this action failed in the middle of this critical section, so to allow the
	// command to be called again we don't error on the uninstall
	//
	// the install error below will include an error about the service still existing if this failed
	// to uninstall (really this should never fail, but the unexpected can happen)
	_ = UninstallService(topPath)

	// re-install service
	pt.Describe("Installing service")
	err = InstallService(topPath, ownership, username, groupName)
	if err != nil {
		pt.Describe("Failed to install service")
		// error context already added by InstallService

		// this is now in a bad state, because the service is uninstall and now the service failed to install
		return err
	}
	pt.Describe("Installed service")

	// start the service
	pt.Describe("Starting service")
	err = StartService(topPath)
	if err != nil {
		pt.Describe("Failed to start service")
		// error context already added by InstallService

		// this is now in a bad state, because the service is not running and failed to install
		return err
	}

	// **end critical section**
	// service is now re-created and started

	return nil
}
