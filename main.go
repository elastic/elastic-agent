// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

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

	err = cmd.CheckNativePlatformCompat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		return
	}

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		return
	}
	defer pj.Close()

	rand.Seed(time.Now().UnixNano())
	command := cmd.NewCommand()
	err = command.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
}
