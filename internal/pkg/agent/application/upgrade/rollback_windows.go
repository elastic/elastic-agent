// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package upgrade

import (
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// delay after agent restart is performed to allow agent to tear down all the processes
	// important mainly for windows, as it prevents removing files which are in use
	afterRestartDelay = 20 * time.Second
)

func InvokeCmdWithArgs(executable string, args ...string) *exec.Cmd {
	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.Command(executable, args...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Signals are sent to process groups, and child process are part of the
		// parent's process group. So to send a signal to a
		// child process and not have it also affect ourselves
		// (the parent process), the child needs to be created in a new
		// process group.
		//
		// Creating a child with CREATE_NEW_PROCESS_GROUP disables CTLR_C_EVENT
		// handling for the child, so the only way to gracefully stop it is with
		// a CTRL_BREAK_EVENT signal.
		// https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
		//
		// Watcher process will also need a console in order to receive CTRL_BREAK_EVENT on windows.
		// Elastic Agent main process running as a service does not have a console allocated and the watcher process will also
		// outlive its parent during an upgrade operation so we add the CREATE_NEW_CONSOLE flag.
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}
