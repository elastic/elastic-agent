// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/core/logger"
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
		// outlive its parent during an upgrade operation so we add the CREATE_NEW_PROCESS_GROUP flag and allocate a new console
		// to be inherited by the watcher process in StartWatcherCommand.
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}

func StartWatcherCmd(log *logger.Logger, createCmd cmdFactory, opts ...WatcherInvocationOpt) (*exec.Cmd, error) {

	invocationOpts := applyWatcherInvocationOpts(opts...)

	// allocConsole
	r1, _, consoleErr := allocConsoleProc.Call()
	if r1 == 0 {
		if !errors.Is(consoleErr, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("error allocating console: %w", consoleErr)
		}
		log.Warnf("Already possessing a console")
	}
	cmd := createCmd()
	log.Infow("Starting upgrade watcher", "path", cmd.Path, "args", cmd.Args, "env", cmd.Env, "dir", cmd.Dir)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Upgrade Watcher: %w", err)
	}
	list, consoleErr := getConsoleProcessList()
	if consoleErr != nil {
		log.Warnf("failed to get console process list: %v", consoleErr)
	} else {
		log.Debugf("Found console processes %v", list)
	}
	// free console
	r1, _, consoleErr = freeConsoleProc.Call()
	if r1 == 0 {
		return nil, fmt.Errorf("error freeing console: %w", consoleErr)
	}
	upgradeWatcherPID := cmd.Process.Pid
	agentPID := os.Getpid()

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Infow("Upgrade Watcher exited with error", "agent.upgrade.watcher.process.pid", agentPID, "agent.process.pid", upgradeWatcherPID, "error.message", err)
		}
		if invocationOpts.postWatchHook != nil {
			invocationOpts.postWatchHook()
		}
	}()

	return cmd, nil
}

// getConsoleProcessList retrieves the list of process IDs attached to the current console
func getConsoleProcessList() ([]uint32, error) {
	// Allocate a buffer for PIDs
	const maxProcs = 64
	pids := make([]uint32, maxProcs)

	r1, _, err := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(maxProcs),
	)

	count := uint32(r1)
	if count == 0 {
		return nil, err
	}

	return pids[:count], nil
}
