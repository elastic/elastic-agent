// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package handlers

import (
	"fmt"
	"os/user"
)

// currentEffectiveIDs returns the SID of the current user and primary group,
// matching the SID strings that install.FindUID and install.FindGID return on
// Windows. The os/user.Current() pitfall described in the Unix variant does
// not apply on Windows — the process token is the source of truth and
// user.Current() reads it correctly.
func currentEffectiveIDs() (string, string, error) {
	u, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current user: %w", err)
	}
	return u.Uid, u.Gid, nil
}
