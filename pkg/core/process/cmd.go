// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !linux && !darwin

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = kernel32.NewProc("AttachConsole")
	procFreeConsole   = kernel32.NewProc("FreeConsole")

	// consoleMu serializes console operations. A Windows process can only be
	// attached to one console at a time, so concurrent attachAndBreak calls
	// must be serialized.
	consoleMu sync.Mutex
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
		// Signals are sent to process groups, and child process are part of the
		// parent's process group. So to send a signal to a
		// child process and not have it also affect ourselves
		// (the parent process), the child needs to be created in a new
		// process group.
		//
		// Creating a child with CREATE_NEW_PROCESS_GROUP disables CTRL_C_EVENT
		// handling for the child, so the only way to gracefully stop it is with
		// a CTRL_BREAK_EVENT signal.
		// https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}

	return cmd, nil
}

// WithNewConsole is a CmdOption that gives the child process its own hidden
// console. This is required for attachAndBreak to deliver CTRL_BREAK_EVENT
// when the parent runs as a Windows service with no console.
//
// Use this for component processes (beats) that need graceful shutdown via
// CTRL_BREAK_EVENT. The OTel collector subprocess does not need this because
// it is stopped via stdin pipe closure.
func WithNewConsole() CmdOption {
	return func(c *exec.Cmd) error {
		if c.SysProcAttr == nil {
			c.SysProcAttr = &syscall.SysProcAttr{}
		}
		c.SysProcAttr.CreationFlags |= windows.CREATE_NEW_CONSOLE
		c.SysProcAttr.HideWindow = true
		return nil
	}
}

// killCmd calls Process.Kill
func killCmd(proc *os.Process) error {
	return proc.Kill()
}

// terminateCmd sends CTRL_BREAK_EVENT to the process for graceful shutdown.
// It first tries a direct send which works when a console is already attached
// (e.g. running from a terminal). If that fails with ERROR_INVALID_HANDLE
// (typical when running as a Windows service with no console), it falls back
// to attaching to the child's console for delivery.
func terminateCmd(proc *os.Process) error {
	err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(proc.Pid))
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		return err
	}
	// No console attached — fall back to attaching to the child's console.
	return attachAndBreak(proc)
}

// attachAndBreak delivers CTRL_BREAK_EVENT to a child process that was created
// with CREATE_NEW_CONSOLE (via WithNewConsole).
//
// On Windows, GenerateConsoleCtrlEvent requires the caller to share a console
// with the target. When elastic-agent runs as a Windows service there is no
// console, so the direct call fails. The child has its own console (from
// CREATE_NEW_CONSOLE), so we attach to it, send the event, then detach.
//
// These steps are serialized with consoleMu because a process can only be
// attached to one console at a time.
//
// See: https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent
// See: https://github.com/elastic/elastic-agent/issues/7756
func attachAndBreak(proc *os.Process) error {
	consoleMu.Lock()
	defer consoleMu.Unlock()

	pid := uint32(proc.Pid)

	// Attach to the child's console so we can send it CTRL_BREAK_EVENT.
	r1, _, err := procAttachConsole.Call(uintptr(pid))
	if r1 == 0 {
		return fmt.Errorf("AttachConsole(%d) failed: %w", pid, err)
	}

	sendErr := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid)

	// Detach from the child's console.
	procFreeConsole.Call()

	return sendErr
}
