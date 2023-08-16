// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.elastic.co/apm"
	apmtransport "go.elastic.co/apm/transport"
	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/logp"
	monitoringLib "github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent-libs/service"
	"github.com/elastic/elastic-agent-system-metrics/report"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/migration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/server"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/version"
)

const (
	agentName            = "elastic-agent"
	fleetInitTimeoutName = "FLEET_SERVER_INIT_TIMEOUT"
)

type cfgOverrider func(cfg *configuration.Configuration)

func newRunCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the Elastic Agent",
		Long:  "This command starts the Elastic Agent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// FIXME: remove this — testing only!
			time.Sleep(10 * time.Second)
			return errors.New("deliberately crashing agent very early")

			// done very early so the encrypted store is never used
			disableEncryptedStore, _ := cmd.Flags().GetBool("disable-encrypted-store")
			if disableEncryptedStore {
				storage.DisableEncryptionDarwin()
			}
			fleetInitTimeout, _ := cmd.Flags().GetDuration("fleet-init-timeout")
			testingMode, _ := cmd.Flags().GetBool("testing-mode")
			if err := run(nil, testingMode, fleetInitTimeout); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())

				return err
			}
			return nil
		},
	}

	// --disable-encrypted-store only has meaning on Mac OS, and it disables the encrypted disk store
	// feature of the Elastic Agent. On Mac OS root privileges are required to perform the disk
	// store encryption, by setting this flag it disables that feature and allows the Elastic Agent to
	// run as non-root.
	cmd.Flags().Bool("disable-encrypted-store", false, "Disable the encrypted disk storage (Only useful on Mac OS)")

	// --testing-mode is a hidden flag that spawns the Elastic Agent in testing mode
	// it is hidden because we really don't want users to execute Elastic Agent to run
	// this way, only the integration testing framework runs the Elastic Agent in this mode
	cmd.Flags().Bool("testing-mode", false, "Run with testing mode enabled")

	cmd.Flags().Duration("fleet-init-timeout", envTimeout(fleetInitTimeoutName), " Sets the initial timeout when starting up the fleet server under agent")
	_ = cmd.Flags().MarkHidden("testing-mode")

	return cmd
}

func run(override cfgOverrider, testingMode bool, fleetInitTimeout time.Duration, modifiers ...component.PlatformModifier) error {
	// Windows: Mark service as stopped.
	// After this is run, the service is considered by the OS to be stopped.
	// This must be the first deferred cleanup task (last to execute).
	defer func() {
		service.NotifyTermination()
		service.WaitExecutionDone()
	}()

	if err := handleUpgrade(); err != nil {
		return fmt.Errorf("error checking for and handling upgrade: %w", err)
	}

	locker := filelock.NewAppLocker(paths.Data(), paths.AgentLockFileName)
	if err := locker.TryLock(); err != nil {
		return err
	}
	defer func() {
		_ = locker.Unlock()
	}()

	service.BeforeRun()
	defer service.Cleanup()

	// register as a service
	stop := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	var stopBeat = func() {
		close(stop)
	}

	defer cancel()
	go service.ProcessWindowsControlEvents(stopBeat)

	cfg, err := loadConfig(ctx, override)
	if err != nil {
		return err
	}

	logLvl := logger.DefaultLogLevel
	if cfg.Settings.LoggingConfig != nil {
		logLvl = cfg.Settings.LoggingConfig.Level
	}
	baseLogger, err := logger.NewFromConfig("", cfg.Settings.LoggingConfig, true)
	if err != nil {
		return err
	}

	l := baseLogger.With("log", map[string]interface{}{
		"source": agentName,
	})

	// Make sure to flush any buffered logs before we're done.
	defer l.Sync() //nolint:errcheck // flushing buffered logs is best effort.

	cfg, err = tryDelayEnroll(ctx, l, cfg, override)
	if err != nil {
		err = errors.New(err, "failed to perform delayed enrollment")
		l.Error(err)
		return err
	}
	pathConfigFile := paths.AgentConfigFile()

	// agent ID needs to stay empty in bootstrap mode
	createAgentID := true
	if cfg.Fleet != nil && cfg.Fleet.Server != nil && cfg.Fleet.Server.Bootstrap {
		createAgentID = false
	}

	// Ensure we have the agent secret created.
	// The secret is not created here if it exists already from the previous enrollment.
	// This is needed for compatibility with agent running in standalone mode,
	// that writes the agentID into fleet.enc (encrypted fleet.yml) before even loading the configuration.
	err = secret.CreateAgentSecret(ctx)
	if err != nil {
		return fmt.Errorf("failed to read/write secrets: %w", err)
	}

	// Migrate .yml files if the corresponding .enc does not exist

	// the encrypted config does not exist but the unencrypted file does
	err = migration.MigrateToEncryptedConfig(ctx, l, paths.AgentConfigYmlFile(), paths.AgentConfigFile())
	if err != nil {
		return errors.New(err, "error migrating fleet config")
	}

	// the encrypted state does not exist but the unencrypted file does
	err = migration.MigrateToEncryptedConfig(ctx, l, paths.AgentStateStoreYmlFile(), paths.AgentStateStoreFile())
	if err != nil {
		return errors.New(err, "error migrating agent state")
	}

	agentInfo, err := info.NewAgentInfoWithLog(ctx, defaultLogLevel(cfg, logLvl.String()), createAgentID)
	if err != nil {
		return errors.New(err,
			"could not load agent info",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	// Ensure that the log level now matches what is configured in the agentInfo.
	if agentInfo.LogLevel() != "" {
		var lvl logp.Level
		err = lvl.Unpack(agentInfo.LogLevel())
		if err != nil {
			l.Error(errors.New(err, "failed to parse agent information log level"))
		} else {
			logLvl = lvl
			logger.SetLevel(lvl)
		}
	}

	// initiate agent watcher
	if err := upgrade.InvokeWatcher(l); err != nil {
		// we should not fail because watcher is not working
		l.Error(errors.New(err, "failed to invoke rollback watcher"))
	}

	if allowEmptyPgp, _ := release.PGP(); allowEmptyPgp {
		l.Info("Elastic Agent has been built with security disabled. Elastic Agent will not verify signatures of upgrade artifact.")
	}

	execPath, err := reexecPath()
	if err != nil {
		return err
	}
	rexLogger := l.Named("reexec")
	rex := reexec.NewManager(rexLogger, execPath)

	tracer, err := initTracer(agentName, release.Version(), cfg.Settings.MonitoringConfig)
	if err != nil {
		return fmt.Errorf("could not initiate APM tracer: %w", err)
	}
	if tracer != nil {
		l.Info("APM instrumentation enabled")
		defer func() {
			tracer.Flush(nil)
			tracer.Close()
		}()
	} else {
		l.Info("APM instrumentation disabled")
	}

	coord, configMgr, composable, err := application.New(ctx, l, baseLogger, logLvl, agentInfo, rex, tracer, testingMode, fleetInitTimeout, configuration.IsFleetServerBootstrap(cfg.Fleet), modifiers...)
	if err != nil {
		return err
	}
	defer composable.Close()

	serverStopFn, err := setupMetrics(l, cfg.Settings.DownloadConfig.OS(), cfg.Settings.MonitoringConfig, tracer, coord)
	if err != nil {
		return err
	}
	defer func() {
		_ = serverStopFn()
	}()

	diagHooks := diagnostics.GlobalHooks()
	diagHooks = append(diagHooks, coord.DiagnosticHooks()...)
	control := server.New(l.Named("control"), agentInfo, coord, tracer, diagHooks, cfg.Settings.GRPC)

	// if the configMgr implements the TestModeConfigSetter in means that Elastic Agent is in testing mode and
	// the configuration will come in over the control protocol, so we set the config setting on the control protocol
	// server so when the configuration comes in it gets passed to the coordinator
	testingSetter, ok := configMgr.(server.TestModeConfigSetter)
	if ok {
		control.SetTestModeConfigSetter(testingSetter)
	}

	// start the control listener
	if err := control.Start(); err != nil {
		return err
	}
	defer control.Stop()

	appDone := make(chan bool)
	appErr := make(chan error)
	// Spawn the main Coordinator goroutine
	go func() {
		err := coord.Run(ctx)
		close(appDone)
		appErr <- err
	}()

	// listen for signals
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	isRex := false
	logShutdown := true
LOOP:
	for {
		select {
		case <-stop:
			l.Info("service.ProcessWindowsControlEvents invoked stop function. Shutting down")
			break LOOP
		case <-appDone:
			l.Info("application done, coordinator exited")
			logShutdown = false
			break LOOP
		case <-rex.ShutdownChan():
			l.Info("reexec shutdown channel triggered")
			isRex = true
			logShutdown = false
			break LOOP
		case sig := <-signals:
			l.Infof("signal %q received", sig)
			if sig == syscall.SIGHUP {
				rexLogger.Infof("SIGHUP triggered re-exec")
				isRex = true
				rex.ReExec(nil)
			} else {
				break LOOP
			}
		}
	}

	if logShutdown {
		l.Info("Shutting down Elastic Agent and sending last events...")
	}
	cancel()
	err = <-appErr

	if logShutdown {
		l.Info("Shutting down completed.")
	}
	if isRex {
		rex.ShutdownComplete()
	}
	return err
}

func loadConfig(ctx context.Context, override cfgOverrider) (*configuration.Configuration, error) {
	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	if err := getOverwrites(ctx, rawConfig); err != nil {
		return nil, errors.New(err, "could not read overwrites")
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not parse configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	if override != nil {
		override(cfg)
	}

	return cfg, nil
}

func reexecPath() (string, error) {
	// set executable path to symlink instead of binary
	// in case of updated symlinks we should spin up new agent
	potentialReexec := filepath.Join(paths.Top(), agentName)

	// in case it does not exists fallback to executable
	if _, err := os.Stat(potentialReexec); os.IsNotExist(err) {
		return os.Executable()
	}

	return potentialReexec, nil
}

func getOverwrites(ctx context.Context, rawConfig *config.Config) error {
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return err
	}

	if !cfg.Fleet.Enabled {
		// overrides should apply only for fleet mode
		return nil
	}
	path := paths.AgentConfigFile()
	store := storage.NewEncryptedDiskStore(ctx, path)

	reader, err := store.Load()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// no fleet file ignore
		return nil
	} else if err != nil {
		return errors.New(err, "could not initialize config store",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	config, err := config.NewConfigFrom(reader)
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("fail to read configuration %s for the elastic-agent", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	err = rawConfig.Merge(config)
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("fail to merge configuration with %s for the elastic-agent", path),
			errors.TypeConfig,
			errors.M(errors.MetaKeyPath, path))
	}

	return nil
}

func defaultLogLevel(cfg *configuration.Configuration, currentLevel string) string {
	if configuration.IsStandalone(cfg.Fleet) {
		// for standalone always take the one from config and don't override
		return currentLevel
	}

	defaultLogLevel := logger.DefaultLogLevel.String()
	if configuredLevel := cfg.Settings.LoggingConfig.Level.String(); configuredLevel != "" && configuredLevel != defaultLogLevel {
		// predefined log level
		return configuredLevel
	}

	return defaultLogLevel
}

func tryDelayEnroll(ctx context.Context, logger *logger.Logger, cfg *configuration.Configuration, override cfgOverrider) (*configuration.Configuration, error) {
	enrollPath := paths.AgentEnrollFile()
	if _, err := os.Stat(enrollPath); err != nil {
		//nolint:nilerr // ignore the error, this is expected
		// no enrollment file exists or failed to stat it; nothing to do
		return cfg, nil
	}
	contents, err := ioutil.ReadFile(enrollPath)
	if err != nil {
		return nil, errors.New(
			err,
			"failed to read delay enrollment file",
			errors.TypeFilesystem,
			errors.M("path", enrollPath))
	}
	var options enrollCmdOption
	err = yaml.Unmarshal(contents, &options)
	if err != nil {
		return nil, errors.New(
			err,
			"failed to parse delay enrollment file",
			errors.TypeConfig,
			errors.M("path", enrollPath))
	}
	options.DelayEnroll = false
	options.FleetServer.SpawnAgent = false
	c, err := newEnrollCmd(
		ctx,
		logger,
		&options,
		paths.ConfigFile(),
	)
	if err != nil {
		return nil, err
	}
	err = c.Execute(ctx, cli.NewIOStreams())
	if err != nil {
		return nil, err
	}
	err = os.Remove(enrollPath)
	if err != nil {
		logger.Warn(errors.New(
			err,
			"failed to remove delayed enrollment file",
			errors.TypeFilesystem,
			errors.M("path", enrollPath)))
	}
	logger.Info("Successfully performed delayed enrollment of this Elastic Agent.")
	return loadConfig(ctx, override)
}

func initTracer(agentName, version string, mcfg *monitoringCfg.MonitoringConfig) (*apm.Tracer, error) {
	apm.DefaultTracer.Close()

	if !mcfg.Enabled || !mcfg.MonitorTraces {
		return nil, nil
	}

	cfg := mcfg.APM

	//nolint:godox // the TODO is intentional
	// TODO(stn): Ideally, we'd use apmtransport.NewHTTPTransportOptions()
	// but it doesn't exist today. Update this code once we have something
	// available via the APM Go agent.
	const (
		envVerifyServerCert = "ELASTIC_APM_VERIFY_SERVER_CERT"
		envServerCert       = "ELASTIC_APM_SERVER_CERT"
		envCACert           = "ELASTIC_APM_SERVER_CA_CERT_FILE"
	)
	if cfg.TLS.SkipVerify {
		os.Setenv(envVerifyServerCert, "false")
		defer os.Unsetenv(envVerifyServerCert)
	}
	if cfg.TLS.ServerCertificate != "" {
		os.Setenv(envServerCert, cfg.TLS.ServerCertificate)
		defer os.Unsetenv(envServerCert)
	}
	if cfg.TLS.ServerCA != "" {
		os.Setenv(envCACert, cfg.TLS.ServerCA)
		defer os.Unsetenv(envCACert)
	}

	ts, err := apmtransport.NewHTTPTransport()
	if err != nil {
		return nil, err
	}

	if len(cfg.Hosts) > 0 {
		hosts := make([]*url.URL, 0, len(cfg.Hosts))
		for _, host := range cfg.Hosts {
			u, err := url.Parse(host)
			if err != nil {
				return nil, fmt.Errorf("failed parsing %s: %w", host, err)
			}
			hosts = append(hosts, u)
		}
		ts.SetServerURL(hosts...)
	}
	if cfg.APIKey != "" {
		ts.SetAPIKey(cfg.APIKey)
	} else {
		ts.SetSecretToken(cfg.SecretToken)
	}

	return apm.NewTracerOptions(apm.TracerOptions{
		ServiceName:        agentName,
		ServiceVersion:     version,
		ServiceEnvironment: cfg.Environment,
		Transport:          ts,
	})
}

func setupMetrics(
	logger *logger.Logger,
	operatingSystem string,
	cfg *monitoringCfg.MonitoringConfig,
	tracer *apm.Tracer,
	coord *coordinator.Coordinator,
) (func() error, error) {
	if err := report.SetupMetrics(logger, agentName, version.GetDefaultVersion()); err != nil {
		return nil, err
	}

	// start server for stats
	endpointConfig := api.Config{
		Enabled: true,
		Host:    monitoring.AgentMonitoringEndpoint(operatingSystem, cfg),
	}

	s, err := monitoring.NewServer(logger, endpointConfig, monitoringLib.GetNamespace, tracer, coord, isProcessStatsEnabled(cfg), operatingSystem)
	if err != nil {
		return nil, errors.New(err, "could not start the HTTP server for the API")
	}
	s.Start()

	// return server stopper
	return s.Stop, nil
}

func isProcessStatsEnabled(cfg *monitoringCfg.MonitoringConfig) bool {
	return cfg != nil && cfg.HTTP.Enabled
}

// handleUpgrade checks if agent is being run as part of an
// ongoing upgrade operation, i.e. being re-exec'd and performs
// any upgrade-specific work, if needed.
func handleUpgrade() error {
	upgradeMarker, err := upgrade.LoadMarker()
	if err != nil {
		return fmt.Errorf("unable to load upgrade marker to check if Agent is being upgraded: %w", err)
	}

	if upgradeMarker == nil {
		// We're not being upgraded. Nothing more to do.
		return nil
	}

	if err := ensureInstallMarkerPresent(); err != nil {
		return err
	}

	if err := upgrade.EnsureServiceConfigUpToDate(); err != nil {
		return err
	}

	return nil
}

func ensureInstallMarkerPresent() error {
	// In v8.8.0, we introduced a new installation marker file to indicate that
	// an Agent was running as installed. When an installed Agent that's older
	// than v8.8.0 is upgraded, this installation marker file is not present.
	// So, in such cases, we need to create it manually post-upgrade.
	// Otherwise, the upgrade will be unsuccessful (see
	// https://github.com/elastic/elastic-agent/issues/2645).

	// Only an installed Elastic Agent can be self-upgraded. So, if the
	// installation marker file is already present, we're all set.
	if info.RunningInstalled() {
		return nil
	}

	// Otherwise, we're being upgraded from a version of an installed Agent
	// that didn't use an installation marker file (that is, before v8.8.0).
	// So create the file now.
	if err := info.CreateInstallMarker(paths.Top()); err != nil {
		return fmt.Errorf("unable to create installation marker file during upgrade: %w", err)
	}

	return nil
}
