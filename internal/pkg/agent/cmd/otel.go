// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"context"
	goerrors "errors"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/elastic/elastic-agent-libs/service"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
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

	var otelStartWg sync.WaitGroup
	var errs []error
	var awaiters awaiters

	otelAwaiter := make(chan struct{})
	awaiters = append(awaiters, otelAwaiter)

	otelStartWg.Add(1)
	go func() {
		otelStartWg.Done()
		if err := otel.Run(ctx, stop, configFiles); err != nil {
			errs = append(errs, err)
			// otel collector finished with an error, exit run loop
			cancel()
		}

		// close awaiter handled in run loop
		close(otelAwaiter)
	}()

	// wait for otel to start
	otelStartWg.Wait()

	if err := runElasticAgent(
		ctx,
		cancel,
		nil,      // no config overrides
		stop,     // service hook
		false,    // not in testing mode
		0,        // no fleet config
		true,     // is otel mode
		awaiters, // wait for otel to finish
	); err != nil && !errors.Is(err, context.Canceled) {
		errs = append(errs, err)
	}

	return goerrors.Join(errs...)

}
