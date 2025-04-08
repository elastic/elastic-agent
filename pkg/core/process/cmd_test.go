// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package process

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGetCmdAndTerminateCmd ensures the process started by this package
// can be gracefully terminated.
//
// This requires two things:
//  1. getCmd sets the correct SysProcAttr according to the OS
//  2. terminateCmd sends the correct signal according to the OS
//
// On Linux and MacOS, no attribute needs to be set on SysProcAttr
// and terminateCmd send SIGTERM.
// On Windows the process needs the CREATE_NEW_PROCESS_GROUP flag
// and terminateCmd needs to send the CTRL+BREAK event, which the
// Go runtime translates into a syscall.SIGINT.
//
// If this test is failing, run go test with -v so all the output
// of the child process is sent to stdout
func TestGetCmdAndTerminateCmd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %s", err)
	}
	testBinary := filepath.Join(wd, "testsignal", "testsignal")

	if runtime.GOOS == "windows" {
		testBinary += ".exe"
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	cmd, err := getCmd(ctx, testBinary, nil, os.Getuid(), os.Getgid(), t.Name())
	if err != nil {
		t.Fatalf("'getCmd' failed: %s", err)
	}

	out, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("cannot get stderr pipe for child process: %s", err)
	}
	sc := bufio.NewScanner(out)

	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start child process: %s", err)
	}

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

	expectedMsg := "Got signal: "
	if runtime.GOOS == "windows" {
		expectedMsg += syscall.SIGINT.String()
	} else {
		expectedMsg += syscall.SIGTERM.String()
	}

	for sc.Scan() {
		line := sc.Text()
		if testing.Verbose() {
			t.Log("Child process output:", line)
		}
		if strings.Contains(line, expectedMsg) {
			break
		}
	}

	// Drain the stdout and wait for the child process to exit.
	// Because we called cmd.StderrPipe() we need to drain the
	// pipe before calling cmd.Wait.
	if testing.Verbose() {
		for sc.Scan() {
			line := sc.Text()
			t.Log("Process Output:", line)
		}
		return
	} else {
		_, _ = io.Copy(io.Discard, out)
	}

	// Wait to ensure the child process exits successfully
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd did not finish successfully: %s", err)
	}

	if cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("process did not finish successfully, exit code: %d", cmd.ProcessState.ExitCode())
	}
}
