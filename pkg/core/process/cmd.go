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
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole    = kernel32.NewProc("AttachConsole")
	procFreeConsole      = kernel32.NewProc("FreeConsole")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")

	// consoleMu serializes console operations. A Windows process can only be
	// attached to one console at a time, so concurrent attachAndBreak calls
	// must be serialized.
	consoleMu sync.Mutex
)

func getCmd(ctx context.Context, path string, env []string, uid, gid int, arg ...string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	if ctx == nil {
		cmd = exec.Command(path, arg...) //nolint:noctx // ctx is intentionally optional for callers that don't need cancellation
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

// HasConsole returns true if the current process has a console attached.
// When running as a Windows service there is no console. Use this to
// decide whether child processes need their own console via WithNewConsole.
func HasConsole() bool {
	r1, _, _ := procGetConsoleWindow.Call()
	return r1 != 0
}

// WithNewConsole is a StartOption that gives the child process its own hidden
// console via CREATE_NEW_CONSOLE. This is required for attachAndBreak to
// deliver CTRL_BREAK_EVENT when the parent has no console (Windows service).
//
// When the parent already has a console, child processes inherit it and
// CTRL_BREAK_EVENT can be delivered directly — WithNewConsole is not needed
// and should not be used, because it isolates the child onto a separate
// console which requires the more complex attachAndBreak path.
//
// Use HasConsole to decide whether to apply this option.
func WithNewConsole() StartOption {
	return func(cfg *StartConfig) {
		cfg.newConsole = true
		cfg.cmdOpts = append(cfg.cmdOpts, func(c *exec.Cmd) error {
			if c.SysProcAttr == nil {
				c.SysProcAttr = &syscall.SysProcAttr{}
			}
			c.SysProcAttr.CreationFlags |= windows.CREATE_NEW_CONSOLE
			c.SysProcAttr.HideWindow = true
			return nil
		})
	}
}

// killCmd calls Process.Kill
func killCmd(proc *os.Process) error {
	return proc.Kill()
}

// terminateCmd sends CTRL_BREAK_EVENT to the process for graceful shutdown.
//
// If the process has its own console (newConsole=true, from WithNewConsole),
// we must use attachAndBreak because the direct GenerateConsoleCtrlEvent
// sends to the caller's console, not the child's — the event is silently
// lost even though the call returns success.
//
// For processes that share the caller's console (newConsole=false), the
// direct call works. If it fails with ERROR_INVALID_HANDLE (no console,
// e.g. running as a Windows service), we fall back to attachAndBreak.
func terminateCmd(proc *os.Process, newConsole bool) error {
	if newConsole {
		return attachAndBreak(proc)
	}
	err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(proc.Pid)) //nolint:gosec // PID is always non-negative
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

	pid := uint32(proc.Pid) //nolint:gosec // PID is always non-negative

	// Attach to the child's console so we can send it CTRL_BREAK_EVENT.
	r1, _, err := procAttachConsole.Call(uintptr(pid))
	if r1 == 0 {
		return fmt.Errorf("AttachConsole(%d) failed: %w", pid, err)
	}

	sendErr := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid)

	// Detach from the child's console.
	_, _, _ = procFreeConsole.Call()

	return sendErr
}
