// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package upgrade

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 2 * time.Second
)

func InvokeCmdWithArgs(executable string, args ...string) *exec.Cmd {
	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.Command(executable, args...)

	var cred = &syscall.Credential{
		Uid:         uint32(os.Getuid()), //nolint:gosec // int -> uint32 no overflow is possible since os.Getuid() should return a value compatible with uint32
		Gid:         uint32(os.Getgid()), //nolint:gosec // int -> uint32 no overflow is possible since os.Getgid() should return a value compatible with uint32
		Groups:      nil,
		NoSetGroups: true,
	}
	var sysproc = &syscall.SysProcAttr{
		Credential: cred,
		Setsid:     true,
	}
	cmd.SysProcAttr = sysproc
	return cmd
}
