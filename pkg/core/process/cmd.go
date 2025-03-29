// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !linux && !darwin

package process

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func getCmd(ctx context.Context, path string, env []string, uid, gid int, arg ...string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	if ctx == nil {
		cmd = exec.Command(path, arg...)
	} else {
		cmd = exec.CommandContext(ctx, path, arg...)
	}
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Dir = filepath.Dir(path)

	return cmd, nil
}

// killCmd calls Process.Kill
func killCmd(proc *os.Process) error {
	return proc.Kill()
}

// terminateCmd sends the CTRL+C (SIGINT) to the process
func terminateCmd(proc *os.Process) error {
	// Send the CTRL+C signal that is tread as a SIGINT
	// https://learn.microsoft.com/en-us/windows/console/ctrl-c-and-ctrl-break-signals
	return windows.GenerateConsoleCtrlEvent(0, uint32(proc.Pid))
}
