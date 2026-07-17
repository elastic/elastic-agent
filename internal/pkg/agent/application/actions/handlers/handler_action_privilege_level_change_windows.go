// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package handlers

import (
	"fmt"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// currentEffectiveIDs returns the SID of the current user and primary group,
// matching the SID strings that install.FindUID and install.FindGID return on
// Windows.
func currentEffectiveIDs() (string, string, error) {
	u, err := utils.CurrentFileOwner()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current user: %w", err)
	}
	return u.UID, u.GID, nil
}
