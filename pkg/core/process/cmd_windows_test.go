// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package process

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestTerminateCmdWithoutConsole verifies that terminateCmd can gracefully stop
// a child process even when the parent has no console attached.
//
// When elastic-agent runs as a Windows service, there is no console. The direct
// GenerateConsoleCtrlEvent call fails with ERROR_INVALID_HANDLE. terminateCmd
// must fall back to attachAndBreak: attach to the child's console (created via
// WithNewConsole/CREATE_NEW_CONSOLE), send CTRL_BREAK_EVENT, then detach.
//
// This test simulates the service scenario by freeing the current console
// before starting the child, so neither parent nor child inherits one. The
// child gets its own console via WithNewConsole.
func TestTerminateCmdWithoutConsole(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %s", err)
	}
	testBinary := filepath.Join(wd, "testsignal", "testsignal.exe")

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	// Free the current console BEFORE starting the child to simulate the
	// Windows service scenario where no console exists.
	_, _, _ = procFreeConsole.Call()
	t.Cleanup(func() {
		// Re-allocate a console so subsequent tests (or the test runner)
		// still have one.
		_, _, _ = kernel32.NewProc("AllocConsole").Call()
	})

	cmd, err := getCmd(ctx, testBinary, nil, os.Getuid(), os.Getgid(), t.Name())
	if err != nil {
		t.Fatalf("'getCmd' failed: %s", err)
	}

	// Give the child its own console via WithNewConsole so that
	// attachAndBreak can attach to it and deliver CTRL_BREAK_EVENT.
	if err := WithNewConsole()(cmd); err != nil {
		t.Fatalf("WithNewConsole failed: %s", err)
	}

	out, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("cannot get stderr pipe for child process: %s", err)
	}
	sc := bufio.NewScanner(out)

	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start child process: %s", err)
	}

	// Wait for the child to be ready.
	for sc.Scan() {
		line := sc.Text()
		if testing.Verbose() {
			t.Log("Child process output:", line)
		}
		if strings.Contains(line, "Wait for signal") {
			break
		}
	}

	if err := terminateCmd(cmd.Process); err != nil {
		t.Fatalf("did not expect an error from 'terminateCmd': %s", err)
	}

	expectedMsg := "Got signal: " + syscall.SIGINT.String()
	gotSignal := false
	for sc.Scan() {
		line := sc.Text()
		if testing.Verbose() {
			t.Log("Child process output:", line)
		}
		if strings.Contains(line, expectedMsg) {
			gotSignal = true
			break
		}
	}

	if !gotSignal {
		t.Fatal("child process did not report receiving the expected signal")
	}

	// Drain stderr and wait for exit.
	if testing.Verbose() {
		for sc.Scan() {
			t.Log("Child process output:", sc.Text())
		}
	} else {
		_, _ = io.Copy(io.Discard, out)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd did not finish successfully: %s", err)
	}

	if cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("process did not finish successfully, exit code: %d", cmd.ProcessState.ExitCode())
	}
}
