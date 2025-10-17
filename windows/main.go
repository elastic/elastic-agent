// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build centry && cgo && windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

import "C"

var (
	ctx    context.Context
	cancel context.CancelFunc
)

//export GoRun
func GoRun() C.int {
	var exitCode C.int = 0

	// golang boundry; we cannot allow a panic to exit the goroutine into C
	// that will cause C to just crash and not continue
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n", r)
			fmt.Fprintf(os.Stderr, "stack trace:\n%s\n", debug.Stack())
			exitCode = 2
		}
	}()

	// create the context that is used for the whole process the C code will
	// cancel the context when the service is asked to stop
	ctx, cancel = context.WithCancel(context.Background())

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		return 1
	}
	defer pj.Close()

	command := cmd.NewCommand()
	err = command.ExecuteContext(ctx)
	if errors.Is(err, context.Canceled) {
		// clean exit
		err = nil
	}
	if err != nil {
		var exitCodeErr *cmd.ExitCodeError
		if errors.As(err, &exitCodeErr) {
			// ExitCodeError requirement is that the code has already done the writing to logs and console.
			// Inside of main() it is only used to provide the correct exit code.
			exitCode = C.int(exitCodeErr.ExitCode())
		}
		// not an exit code error but still has an error, this covers the case of an error inside the cobra
		// package. we write this error to stderr so its visible
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		exitCode = 1
	} else {
		// clean exit
		exitCode = 0
	}
	return exitCode
}

//export GoStop
func GoStop() {
	// golang boundry; we cannot allow a panic to exit the goroutine into C
	// that will cause C to just crash and not continue
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic in GoStop: %v\n", r)
			fmt.Fprintf(os.Stderr, "stack trace:\n%s\n", debug.Stack())
		}
	}()

	if cancel != nil {
		cancel()
	}
}

func main() {
	// golang requires that main be defined, but is not used
}
