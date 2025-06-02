// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func newOtelSupervisedCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   otel.EDOTSupevisedCommand,
		Short: "Run EDOT collector in supervised mode",
		Long:  "This command starts the EDOT collector in supervised mode.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			defaultCfg := logger.DefaultLoggingConfig()
			defaultEventLogCfg := logger.DefaultEventLoggingConfig()

			defaultCfg.ToStderr = true
			defaultCfg.ToFiles = false
			defaultEventLogCfg.ToFiles = false
			defaultEventLogCfg.ToStderr = true
			defaultCfg.Level = logger.DefaultLogLevel

			baseLogger, err := logger.NewFromConfig("edot", defaultCfg, defaultEventLogCfg, false)
			if err != nil {
				return err
			}

			if err := prepareEnv(); err != nil {
				return err
			}
			return otel.RunSupervisedCollector(cmd.Context(), baseLogger, streams.In)
		},
		PreRun: func(c *cobra.Command, args []string) {
			// hide inherited flags not to bloat help with flags not related to otel
			hideInheritedFlags(c)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		Hidden:        true,
	}

	cmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		hideInheritedFlags(c)
		c.Root().HelpFunc()(c, s)
	})

	return cmd
}
