// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func newComponentCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component <subcommand>",
		Short: "Tools to work on components",
		Long:  "Tools for viewing current component information and developing new components for Elastic Agent",
	}

	cmd.AddCommand(newComponentSpecCommandWithArgs(args, streams))

	return cmd
}
