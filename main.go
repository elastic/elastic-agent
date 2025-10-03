// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// Setups and Runs agent.
func main() {
	exitCode := 1
	defer func() {
		os.Exit(exitCode) // defer os exit and allow other goroutines to clean up
	}()

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		return
	}
	defer pj.Close()

	command := cmd.NewCommand()
	err = command.Execute()
	if errors.Is(err, context.Canceled) {
		// clean exit
		err = nil
	}
	if err != nil {
		var exitCodeErr *cmd.ExitCodeError
		if errors.As(err, &exitCodeErr) {
			// ExitCodeError requirement is that the code has already done the writing to logs and console.
			// Inside of main() it is only used to provide the correct exit code.
			exitCode = exitCodeErr.ExitCode()
		}
		// not an exit code error but still has an error, this covers the case of an error inside the cobra
		// package. we write this error to stderr so its visible
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		exitCode = 1
	} else {
		// clean exit
		exitCode = 0
	}
}
