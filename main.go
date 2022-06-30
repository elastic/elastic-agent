// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"github.com/elastic/elastic-agent/pkg/core/process"
	"math/rand"
	"os"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
)

// Setups and Runs agent.
func main() {
	if err := cmd.CheckNativePlatformCompat(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		os.Exit(1)
	}

	pj, err := process.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		os.Exit(1)
	}
	defer pj.Close()

	rand.Seed(time.Now().UnixNano())
	command := cmd.NewCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
