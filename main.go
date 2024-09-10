// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// Setups and Runs agent.
func main() {
	var err error
	defer func() {
		if err != nil {
			os.Exit(1) // defer os exit and allow other goroutines to cleanup
		}
	}()

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		return
	}
	defer pj.Close()

	command := cmd.NewCommand()
	err = command.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
}
