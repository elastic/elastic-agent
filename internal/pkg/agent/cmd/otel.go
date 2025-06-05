// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent-libs/service"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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
			supervised, err := cmd.Flags().GetBool(otelSetSupervisedFlagName)
			if err != nil {
				return err
			}
			if err := prepareEnv(); err != nil {
				return err
			}
			return RunCollector(cmd.Context(), cfgFiles, supervised)
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
	cmd.AddCommand(newComponentsCommandWithArgs(args, streams))

	return cmd
}

func hideInheritedFlags(c *cobra.Command) {
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		f.Hidden = true
	})
}

func RunCollector(cmdCtx context.Context, configFiles []string, supervised bool) error {
	var settings *otelcol.CollectorSettings
	if supervised {
		// add stdin config provider
		configProvider, err := agentprovider.NewProvider(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to create config provider: %w", err)
		}
		settings = otel.NewSettings(release.Version(), []string{configProvider.URI()},
			otel.WithConfigProviderFactory(configProvider.NewFactory()),
		)

		// setup logger
		l, err := supervisedGetLogger()
		if err != nil {
			return fmt.Errorf("failed to create logger: %w", err)
		}
		settings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
			return l.Core()
		})}

		settings.DisableGracefulShutdown = false
	} else {
		settings = otel.NewSettings(release.Version(), configFiles)
	}
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

	stopCollector := func() {
		close(stop)
	}

	defer cancel()
	go service.ProcessWindowsControlEvents(stopCollector)

	return otel.Run(ctx, stop, settings)
}

func supervisedGetLogger() (*logger.Logger, error) {
	defaultCfg := logger.DefaultLoggingConfig()
	defaultEventLogCfg := logger.DefaultEventLoggingConfig()

	defaultCfg.ToStderr = true
	defaultCfg.ToFiles = false

	defaultEventLogCfg.ToFiles = false
	defaultEventLogCfg.ToStderr = true
	defaultCfg.Level = logger.DefaultLogLevel

	l, err := logger.NewFromConfig("edot", defaultCfg, defaultEventLogCfg, false)
	if err != nil {
		return nil, err
	}

	return l, err
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
