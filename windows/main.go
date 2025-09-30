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

import "C"

var (
	ctx    context.Context
	cancel context.CancelFunc
)

//export GoRun
func GoRun() {
	var err error
	defer func() {
		if err != nil {
			os.Exit(1) // defer os exit and allow other goroutines to cleanup
		}
	}()

	// create the context that is used for the whole process the C code will
	// cancel the context when the service is asked to stop
	ctx, cancel = context.WithCancel(context.Background())

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		return
	}
	defer pj.Close()

	command := cmd.NewCommand()
	err = command.ExecuteContext(ctx)
	if errors.Is(err, context.Canceled) {
		// set to nil so defer func() doesn't os.Exit(1)
		err = nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
}

//export GoStop
func GoStop() {
	if cancel != nil {
		cancel()
	}
}

func main() {
	// golang requires that main be defined, but is not used
}
