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
	"syscall"

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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Signals are sent to process groups, so to send a signal to a
		// child process and not have it also affect ourselves
		// (the parent process), the child needs to be created in a new
		// process group.
		//
		// Creating a child with CREATE_NEW_PROCESS_GROUP disables CTLR_C_EVENT
		// handling for the child, so the only way to gracefully stop it is with
		// a CTRL_BREAK_EVENT signal.
		// https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}

	return cmd, nil
}

// killCmd calls Process.Kill
func killCmd(proc *os.Process) error {
	return proc.Kill()
}

// terminateCmd sends the CTRL+BREAK (SIGINT) to the process
func terminateCmd(proc *os.Process) error {
	// Because we set CREATE_NEW_PROCESS_GROUP when creating the process,
	// it CTLR_C_EVENT is disabled, so the only way to gracefully terminate
	// the child process is to send a CTRL_BREAK_EVENT.
	// https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(proc.Pid))
}
