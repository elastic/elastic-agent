// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/elastic/elastic-agent-libs/service"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
)

func newOtelCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "otel",
		Short: "Start the Elastic Agent in otel mode",
		Long:  "This command starts the Elastic Agent in otel mode.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgFiles, err := getConfigFiles(cmd, true)
			if err != nil {
				return err
			}
			if err := prepareEnv(); err != nil {
				return err
			}
			return runCollector(cmd.Context(), cfgFiles)
		},
		PreRun: func(c *cobra.Command, args []string) {
			// hide inherited flags not to bloat help with flags not related to otel
			hideInheritedFlags(c)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		hideInheritedFlags(c)
		c.Root().HelpFunc()(c, s)
	})

	setupOtelFlags(cmd.Flags())
	cmd.AddCommand(newValidateCommandWithArgs(args, streams))

	return cmd
}

func hideInheritedFlags(c *cobra.Command) {
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		f.Hidden = true
	})
}

func runCollector(cmdCtx context.Context, configFiles []string) error {
	// Windows: Mark service as stopped.
	// After this is run, the service is considered by the OS to be stopped.
	// This must be the first deferred cleanup task (last to execute).
	defer func() {
		service.NotifyTermination()
		service.WaitExecutionDone()
	}()

	service.BeforeRun()
	defer service.Cleanup()

	stop := make(chan bool)
	ctx, cancel := context.WithCancel(cmdCtx)

	var stopCollector = func() {
		close(stop)
	}

	defer cancel()
	go service.ProcessWindowsControlEvents(stopCollector)

	return otel.Run(ctx, stop, configFiles)
}

func prepareEnv() error {
	if _, ok := os.LookupEnv("STATE_PATH"); !ok {
		// STATE_PATH is not set. Set it to defaultStateDirectory because we do not want to use any of the paths, that are also used by Beats or Agent
		// because a standalone OTel collector must be able to run alongside them without issue.

		// The filestorage extension will handle directory creation since create_directory: true is set by default.
		// If the user hasn’t specified the env:STATE_PATH in filestorage config, they may have opted for a custom path, and the extension will create the directory accordingly.
		// In this case, setting env:STATE_PATH will have no effect.
		if err := os.Setenv("STATE_PATH", defaultStateDirectory); err != nil {
			return err
		}
	}
	return nil
}
