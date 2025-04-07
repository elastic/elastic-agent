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
