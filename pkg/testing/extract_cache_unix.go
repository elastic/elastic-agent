// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package testing

import (
	"errors"
	"syscall"
)

// processAlive reports whether a process with the given pid exists.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	// EPERM means the process exists but belongs to another user.
	return err == nil || errors.Is(err, syscall.EPERM)
}
