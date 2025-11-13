// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !otelexternal

package cmd

import (
	"github.com/spf13/cobra"

	edotCmd "github.com/elastic/elastic-agent/internal/edot/cmd"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func newOtelCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	// embedded into the agent build
	return edotCmd.NewOtelCommandWithArgs(args, streams)
}
