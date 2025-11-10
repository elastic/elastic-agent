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

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/service"

	edotOtelCol "github.com/elastic/elastic-agent/internal/edot/otelcol"
	"github.com/elastic/elastic-agent/internal/edot/otelcol/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/otel/manager"
	"github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	agentBaseDirectory    = "/usr/share/elastic-agent"    // directory that holds all elastic-agent related files
	defaultStateDirectory = agentBaseDirectory + "/state" // directory that will hold the state data
)

func NewOtelCommandWithArgs(args []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "otel",
		Short: "Start the Elastic Agent in otel mode",
		Long:  "This command starts the Elastic Agent in otel mode.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgFiles, err := GetConfigFiles(cmd, true)
			if err != nil {
				return err
			}
			supervised, err := cmd.Flags().GetBool(manager.OtelSetSupervisedFlagName)
			if err != nil {
				return err
			}
			supervisedLoggingLevel, err := cmd.Flags().GetString(manager.OtelSupervisedLoggingLevelFlagName)
			if err != nil {
				return err
			}
			supervisedMonitoringURL, err := cmd.Flags().GetString(manager.OtelSupervisedMonitoringURLFlagName)
			if err != nil {
				return err
			}
			if err := prepareEnv(); err != nil {
				return err
			}
			return RunCollector(cmd.Context(), cfgFiles, supervised, supervisedLoggingLevel, supervisedMonitoringURL)
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

	SetupOtelFlags(cmd.Flags())
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

func RunCollector(cmdCtx context.Context, configFiles []string, supervised bool, supervisedLoggingLevel string, supervisedMonitoringURL string) error {
	settings, err := prepareCollectorSettings(configFiles, supervised, supervisedLoggingLevel)
	if err != nil {
		return fmt.Errorf("failed to prepare collector settings: %w", err)
	}
	// Windows: Mark service as stopped.
	// After this is run, the service is considered by the OS to be stopped.
	// This must be the first deferred cleanup task (last to execute).
	defer func() {
		service.NotifyTermination()
		service.WaitExecutionDone()
	}()

	if supervisedMonitoringURL != "" {
		server, err := monitoring.NewServer(settings.log, supervisedMonitoringURL)
		if err != nil {
			return fmt.Errorf("error create monitoring server: %w", err)
		}
		server.Start()
		defer func() {
			_ = server.Stop()
		}()
	}

	service.BeforeRun()
	defer service.Cleanup()

	stop := make(chan bool)
	ctx, cancel := context.WithCancel(cmdCtx)

	stopCollector := func() {
		close(stop)
	}

	defer cancel()
	if settings.otelSettings.DisableGracefulShutdown { // TODO: Harmonize these settings
		service.HandleSignals(stopCollector, cancel)
	}

	return edotOtelCol.Run(ctx, stop, settings.otelSettings)
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
		settings.otelSettings = edotOtelCol.NewSettings(release.Version(), []string{configProvider.URI()},
			edotOtelCol.WithConfigProviderFactory(configProvider.NewFactory()),
			edotOtelCol.WithConfigConvertorFactory(manager.NewForceExtensionConverterFactory(elasticdiagnostics.DiagnosticsExtensionID.String(), conf)),
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
		settings.otelSettings = edotOtelCol.NewSettings(release.Version(), configFiles, edotOtelCol.WithConfigConvertorFactory(manager.NewForceExtensionConverterFactory(elasticdiagnostics.DiagnosticsExtensionID.String(), conf)))
	}
	return settings, nil
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
