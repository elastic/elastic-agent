// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package install

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// changeUser changes user associated with a service without reinstalling the service itself
func changeUser(topPath string, ownership utils.FileOwner, username string, groupName string, _ string) error {
	serviceName := paths.ServiceName()
	plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", serviceName)

	return changeLaunchdServiceFile(
		serviceName,
		plistPath,
		username,
		groupName,
	)
}
