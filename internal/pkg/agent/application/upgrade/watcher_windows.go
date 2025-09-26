// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package upgrade

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

var (
	kernel32API = windows.NewLazySystemDLL("kernel32.dll")

	freeConsoleProc           = kernel32API.NewProc("FreeConsole")
	procGetConsoleProcessList = kernel32API.NewProc("GetConsoleProcessList")
	allocConsoleProc          = kernel32API.NewProc("AllocConsole")
)

func createTakeDownWatcherCommand(ctx context.Context) *exec.Cmd {
	executable, _ := os.Executable()

	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.CommandContext(ctx, executable, watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
		"--takedown",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
		CreationFlags: windows.DETACHED_PROCESS,
	}
	return cmd
}
