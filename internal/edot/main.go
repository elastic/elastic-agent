// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/edot/beats"
	edotCmd "github.com/elastic/elastic-agent/internal/edot/cmd"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func main() {
	cmd := edotCmd.NewOtelCommandWithArgs(os.Args, cli.NewIOStreams())
	beats.AddCommands(cmd)
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
