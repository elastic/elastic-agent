// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux || darwin

package process

import "os/exec"

// WithNewConsole is a no-op on non-Windows platforms.
func WithNewConsole() CmdOption {
	return func(c *exec.Cmd) error { return nil }
}
