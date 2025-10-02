// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"howett.net/plist"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	LaunchdUserNameKey  = "UserName"
	LaunchdGroupNameKey = "GroupName"
)

// logExternal logs the error to an external log.  On non-windows systems this is a no-op.
func logExternal(msg string) {
}

func getDesiredUser() (string, string, error) {
	serviceName := paths.ServiceName()
	plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", serviceName)

	content, err := os.ReadFile(plistPath)
	if errors.Is(err, fs.ErrNotExist) {
		// not running as a service
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("failed to read plist file %s: %w", plistPath, err)
	}

	dec := plist.NewDecoder(bytes.NewReader(content))
	plistMap := make(map[string]interface{})

	err = dec.Decode(&plistMap)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode service file: %w", err)
	}

	var userName, groupName string
	if u, ok := plistMap[LaunchdUserNameKey]; ok {
		userName = fmt.Sprint(u)
	}

	if g, ok := plistMap[LaunchdGroupNameKey]; ok {
		groupName = fmt.Sprint(g)
	}

	return userName, groupName, nil
}

func dropRootPrivileges(ownership utils.FileOwner) error {
	// change group first, setuid will drop permission to change group
	if ownership.GID > 0 {
		// not necessary, just in case.
		if err := syscall.Setegid(ownership.GID); err != nil {
			return fmt.Errorf("failed to set eGID: %w", err)
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
