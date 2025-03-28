// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// CommitSHA is set by the linker at build time
var CommitSHA string

// logger prints messages to stdout and the windows event log
type logger struct {
	winEventLog interface {
		Error(eid uint32, msg string) error
		Close() error
	}
}

// newLogger creates a new logger
func newLogger() (*logger, error) {
	err := eventlog.InstallAsEventCreate(paths.ServiceName(), eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && !strings.Contains(err.Error(), "registry key already exists") {
		return nil, err
	}

	eLog, err := eventlog.Open(paths.ServiceName())
	if err != nil {
		return nil, err
	}

	return &logger{
		winEventLog: eLog,
	}, nil
}

// Close closes the event log
func (l *logger) Close() {
	_ = l.winEventLog.Close()
}

// Fatal is equivalent to [fmt.Print] followed by a call to [os.Exit](1).
func (l *logger) Fatal(v ...any) {
	msg := fmt.Sprint(v...)
	_ = l.winEventLog.Error(1, msg)
	os.Exit(1)
}

// Fatalf is equivalent to [fmt.Printf] followed by a call to [os.Exit](1).
func (l *logger) Fatalf(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	_ = l.winEventLog.Error(1, msg)
	os.Exit(1)
}

func main() {
	log, err := newLogger()
	if err != nil {
		fmt.Printf("Error creating logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	if CommitSHA == "" {
		// this should never happen
		log.Fatal("No commit SHA provided")
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting executable path: %v\n", err)
	}

	exeAbsPath, err := filepath.Abs(exePath)
	if err != nil {
		log.Fatalf("Error getting executable absolute path: %v\n", err)
	}

	// Fabricate the elastic-agent.exe path that resides inside the data/elastic-agent-{commit-short-sha} directory
	exeTopPath := filepath.Dir(exeAbsPath)
	nestedAgentBinaryPath := filepath.Join(exeTopPath, "data", fmt.Sprintf("elastic-agent-%s", CommitSHA), "elastic-agent.exe")
	if _, err := os.Stat(nestedAgentBinaryPath); err != nil {
		log.Fatalf("Unable to execute elastic-agent.exe at %q: %v\n", nestedAgentBinaryPath, err)
	}

	// Create the arguments
	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}

	g, err := process.CreateJobObject()
	if err != nil {
		log.Fatalf("Unable to create job object: %v\n", err)
	}
	defer func() {
		_ = g.Close()
	}()

	// Create the command
	command := exec.Command(nestedAgentBinaryPath, args...)

	// Forward stdout, stderr, stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin

	// Pass the environment
	command.Env = os.Environ()

	// Run the command
	err = command.Start()
	if err != nil {
		log.Fatalf("Error running command: %v\n", err)
	}

	// Add the process to the job object
	if err := g.Assign(command.Process); err != nil {
		log.Fatalf("Error adding job object: %v\n", err)
	}

	err = command.Wait()
	var exitError *exec.ExitError
	switch {
	case errors.As(err, &exitError):
		exitCode := exitError.ExitCode()
		if exitCode == 0 {
			// Exit with non-zero exit code since we did get an error
			os.Exit(1)
		}
		// Exit with the same exit code
		os.Exit(exitCode)
	case err != nil:
		// Exit with a non-zero exit code
		log.Fatalf("Command failed: %v\n", err)
	}
}
