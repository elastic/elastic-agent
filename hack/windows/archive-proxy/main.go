// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/elastic/elastic-agent/pkg/core/process"
)

var CommitSHA string

func main() {
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

	// Fabricate the elastic-agent.exe path that reside inside the data/elastic-agent-{commit-short-sha} directory
	exeTopPath := filepath.Dir(exeAbsPath)
	nestedAgentBinaryPath := filepath.Join(exeTopPath, "data", fmt.Sprintf("elastic-agent-%s", CommitSHA), "elastic-agent.exe")
	if _, err := os.Stat(nestedAgentBinaryPath); err != nil {
		log.Fatalf("Unable to stat nested agent binary %q: %v\n", nestedAgentBinaryPath, err)
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
