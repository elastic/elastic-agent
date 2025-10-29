// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

const (
	troubleshootMessage = "For help, please see our troubleshooting guide at https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems"
)

// NewCommandWithArgs returns a new edot with the flags and the subcommand.
func NewCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use: "edot [subcommand]",
	}

	otel := newOtelCommandWithArgs(args, streams)
	cmd.AddCommand(otel)

	cmd.Run = otel.Run
	return cmd
}
