// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package main

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func stopCmd(cmd *exec.Cmd) error {
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// This disables the child from receiveing CTRL_C events
		// But isolates other siganls from us, aka the parent
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
}
