// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/elastic/elastic-agent-libs/service"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
)

const (
	configFlagName = "config"
	setFlagName    = "set"
)

func newOtelCommandWithArgs(_ []string, _ *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "otel",
		Short: "Start the Elastic Agent in otel mode",
		Long:  "This command starts the Elastic Agent in otel mode.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgFiles, err := getConfigFiles(cmd)
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
		c.Parent().HelpFunc()(c, s)
	})

	cmd.Flags().StringArray(configFlagName, []string{}, "Locations to the config file(s), note that only a"+
		" single location can be set per flag entry e.g. `--config=file:/path/to/first --config=file:path/to/second`.")

	cmd.Flags().StringArray(setFlagName, []string{}, "Set arbitrary component config property. The component has to be defined in the config file and the flag"+
		" has a higher precedence. Array config properties are overridden and maps are joined. Example --set=processors.batch.timeout=2s")
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
	var resErr error
	var awaiters awaiters

	otelAwaiter := make(chan struct{})
	awaiters = append(awaiters, otelAwaiter)

	otelStartWg.Add(1)
	go func() {
		otelStartWg.Done()
		if err := otel.Run(ctx, stop, configFiles); err != nil {
			resErr = multierror.Append(resErr, err)
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
		resErr = multierror.Append(resErr, err)
	}

	return resErr

}
