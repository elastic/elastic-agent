// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// logExternal logs the error to an external log.  On non-windows systems this is a no-op.
func logExternal(msg string) {
}

func dropRootPrivileges(l *logger.Logger, ownership utils.FileOwner) error {
	// change group first, setuid will drop permission to change group
	if ownership.GID > 0 {
		// not necessary, just in case.
		if err := syscall.Setegid(ownership.GID); err != nil {
			l.Warnf("SETEGID failed with error: %v", err)
		}

		if err := syscall.Setgid(ownership.GID); err != nil {
			return fmt.Errorf("failed to set GID: %w", err)
		}
	}

	if ownership.UID > 0 {
		if err := syscall.Setuid(ownership.UID); err != nil {
			return fmt.Errorf("failed to set UID: %w", err)
		}
	}

	return nil
}

func checkCapabilitiesPerms(agentCapabilitiesPath string, userName string, uid int) error {
	var capabilitiesUID int
	if userName != "" {
		capabilitiesUID = uid
	} else {
		capabilitiesUID = os.Getuid()
	}
	if err := utils.HasStrictExecPermsAndOwnership(agentCapabilitiesPath, capabilitiesUID); err != nil && !os.IsNotExist(err) {
		// capabilities are corrupted, we should not proceed
		return fmt.Errorf("invalid capabilities file permissions: %w", err)
	}

	return nil
}
