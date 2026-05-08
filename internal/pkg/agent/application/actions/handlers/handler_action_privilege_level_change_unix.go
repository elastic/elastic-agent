// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package handlers

import (
	"os"
	"strconv"
)

// currentEffectiveIDs returns the effective UID and GID of the current process
// as decimal strings, matching the representation that install.FindUID and
// install.FindGID return on Unix.
//
// We deliberately use os.Geteuid/Getegid here (the same source as
// utils.HasRoot) rather than os/user.Current(). With CGO_ENABLED=0 on Linux,
// os/user.Current() keys its /etc/passwd lookup on the *real* UID
// (os.Getuid), which after the agent's dropRootPrivileges (run_linux.go:22)
// can still be 0 even though the effective UID is the unprivileged target —
// pushing the privilege-level-change dedup check to fall through and the
// agent to FAILED. See issue #14079.
func currentEffectiveIDs() (string, string, error) {
	return strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid()), nil
}
