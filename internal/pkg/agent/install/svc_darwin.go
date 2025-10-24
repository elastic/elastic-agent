// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"howett.net/plist"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// GetDesiredUser retrieves user and group names as configured in a service file
func GetDesiredUser() (string, string, error) {
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

// changeUser changes user associated with a service without reinstalling the service itself
func changeUser(_ string, _ utils.FileOwner, username string, groupName string, _ string) error {
	serviceName := paths.ServiceName()
	plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", serviceName)

	return changeLaunchdServiceFile(
		serviceName,
		plistPath,
		username,
		groupName,
	)
}
