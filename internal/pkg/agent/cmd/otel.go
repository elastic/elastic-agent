// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/elastic/elastic-agent-libs/service"
<<<<<<< HEAD
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
=======

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/otel/manager"
	"github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
>>>>>>> 47112bda4 ([otel] Implement EDOT diagnostics extension (#10052))
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
	cmd.AddCommand(newComponentsCommandWithArgs(args, streams))
	cmd.AddCommand(newOtelDiagnosticsCommand(streams))

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

	stopCollector := func() {
		close(stop)
	}

	defer cancel()
	go service.ProcessWindowsControlEvents(stopCollector)

<<<<<<< HEAD
	return otel.Run(ctx, stop, configFiles)
=======
	return otel.Run(ctx, stop, settings.otelSettings)
}

type edotSettings struct {
	log          *logger.Logger
	otelSettings *otelcol.CollectorSettings
}

func prepareCollectorSettings(configFiles []string, supervised bool, supervisedLoggingLevel string) (edotSettings, error) {
	var settings edotSettings
	conf := map[string]any{
		"endpoint": paths.DiagnosticsExtensionSocket(),
	}
	if supervised {
		// add stdin config provider
		configProvider, err := agentprovider.NewBufferProvider(os.Stdin)
		if err != nil {
			return settings, fmt.Errorf("failed to create config provider: %w", err)
		}
		settings.otelSettings = otel.NewSettings(release.Version(), []string{configProvider.URI()},
			otel.WithConfigProviderFactory(configProvider.NewFactory()),
			otel.WithConfigConvertorFactory(manager.NewForceExtensionConverterFactory(elasticdiagnostics.DiagnosticsExtensionID.String(), conf)),
		)

		// setup logger
		defaultCfg := logger.DefaultLoggingConfig()
		defaultEventLogCfg := logger.DefaultEventLoggingConfig()

		defaultCfg.ToStderr = true
		defaultCfg.ToFiles = false

		defaultEventLogCfg.ToFiles = false
		defaultEventLogCfg.ToStderr = true

		var logLevelSettingErr error
		if supervisedLoggingLevel != "" {
			if logLevelSettingErr = defaultCfg.Level.Unpack(supervisedLoggingLevel); logLevelSettingErr != nil {
				defaultCfg.Level = logp.InfoLevel
			}
		} else {
			defaultCfg.Level = logp.InfoLevel
		}

		l, err := logger.NewFromConfig("edot", defaultCfg, defaultEventLogCfg, false)
		if err != nil {
			return settings, fmt.Errorf("failed to create logger: %w", err)
		}
		settings.log = l

		if logLevelSettingErr != nil {
			l.Warnf("Fallback to default logging level due to: %v", logLevelSettingErr)
		}

		settings.otelSettings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
			return l.Core()
		})}

		settings.otelSettings.DisableGracefulShutdown = false
	} else {
		settings.otelSettings = otel.NewSettings(release.Version(), configFiles, otel.WithConfigConvertorFactory(manager.NewForceExtensionConverterFactory(elasticdiagnostics.DiagnosticsExtensionID.String(), conf)))
	}
	return settings, nil
>>>>>>> 47112bda4 ([otel] Implement EDOT diagnostics extension (#10052))
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
