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

	"github.com/spf13/cobra"
	"go.elastic.co/apm"
	apmtransport "go.elastic.co/apm/transport"
	"gopkg.in/yaml.v2"

	monitoringLib "github.com/elastic/elastic-agent-libs/monitoring"

	"github.com/elastic/elastic-agent-libs/api"
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
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/server"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/version"
)

const (
	agentName = "elastic-agent"
)

type cfgOverrider func(cfg *configuration.Configuration)

func newRunCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the elastic-agent.",
		Run: func(_ *cobra.Command, _ []string) {
<<<<<<< HEAD
			if err := run(nil); err != nil && !errors.Is(err, context.Canceled) {
=======
			if err := run(nil); err != nil {
				logp.NewLogger("cmd_run").
					Errorw("run command finished with error",
						"error.message", err)
>>>>>>> 567f9e2dce (Improve shutdown logs (#1618) (#1627))
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())

				// TODO: remove it. os.Exit will be called on main and if it's called
				// too early some goroutines with deferred functions related
				// to the shutdown process might not run.
				os.Exit(1)
			}
		},
	}
}

func run(override cfgOverrider, modifiers ...component.PlatformModifier) error {
	// Windows: Mark service as stopped.
	// After this is run, the service is considered by the OS to be stopped.
	// This must be the first deferred cleanup task (last to execute).
	defer func() {
		service.NotifyTermination()
		service.WaitExecutionDone()
	}()

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
	service.HandleSignals(stopBeat, cancel)

	cfg, err := loadConfig(override)
	if err != nil {
		return err
	}

	logger, err := logger.NewFromConfig("", cfg.Settings.LoggingConfig, true)
	if err != nil {
		return err
	}

	cfg, err = tryDelayEnroll(ctx, logger, cfg, override)
	if err != nil {
		err = errors.New(err, "failed to perform delayed enrollment")
		logger.Error(err)
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
	err = secret.CreateAgentSecret()
	if err != nil {
		return fmt.Errorf("failed to read/write secrets: %w", err)
	}

	agentInfo, err := info.NewAgentInfoWithLog(defaultLogLevel(cfg), createAgentID)
	if err != nil {
		return errors.New(err,
			"could not load agent info",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	// initiate agent watcher
	if err := upgrade.InvokeWatcher(logger); err != nil {
		// we should not fail because watcher is not working
		logger.Error(errors.New(err, "failed to invoke rollback watcher"))
	}

	if allowEmptyPgp, _ := release.PGP(); allowEmptyPgp {
		logger.Info("Elastic Agent has been built with security disabled. Elastic Agent will not verify signatures of upgrade artifact.")
	}

	execPath, err := reexecPath()
	if err != nil {
		return err
	}
	rexLogger := logger.Named("reexec")
	rex := reexec.NewManager(rexLogger, execPath)

	tracer, err := initTracer(agentName, release.Version(), cfg.Settings.MonitoringConfig)
	if err != nil {
		return fmt.Errorf("could not initiate APM tracer: %w", err)
	}
	if tracer != nil {
		logger.Info("APM instrumentation enabled")
		defer func() {
			tracer.Flush(nil)
			tracer.Close()
		}()
	} else {
		logger.Info("APM instrumentation disabled")
	}

	coord, err := application.New(logger, agentInfo, rex, tracer, configuration.IsFleetServerBootstrap(cfg.Fleet), modifiers...)
	if err != nil {
		return err
	}

	serverStopFn, err := setupMetrics(logger, cfg.Settings.DownloadConfig.OS(), cfg.Settings.MonitoringConfig, tracer, coord)
	if err != nil {
		return err
	}
	defer func() {
		_ = serverStopFn()
	}()

	diagHooks := diagnostics.GlobalHooks()
	diagHooks = append(diagHooks, coord.DiagnosticHooks()...)
	control := server.New(logger.Named("control"), agentInfo, coord, tracer, diagHooks, cfg.Settings.GRPC)
	// start the control listener
	if err := control.Start(); err != nil {
		return err
	}
	defer control.Stop()

	appDone := make(chan bool)
	appErr := make(chan error)
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
<<<<<<< HEAD
			break LOOP
		case <-appDone:
			logShutdown = false
			break LOOP
		case <-rex.ShutdownChan():
			isRex = true
			logShutdown = false
			break LOOP
=======
			logger.Info("service.HandleSignals invoked stop function. Shutting down")
			breakout = true
		case <-rex.ShutdownChan():
			logger.Info("reexec Shutdown channel triggered")
			reexecing = true
			breakout = true
>>>>>>> 567f9e2dce (Improve shutdown logs (#1618) (#1627))
		case sig := <-signals:
			logger.Infof("signal %q received", sig)
			if sig == syscall.SIGHUP {
<<<<<<< HEAD
				rexLogger.Infof("SIGHUP triggered re-exec")
				isRex = true
				rex.ReExec(nil)
			} else {
				break LOOP
=======
				logger.Infof("signals syscall.SIGHUP received, triggering agent restart")
				rex.ReExec(nil)
			} else {
				breakout = true
			}
		}
		if breakout {
			if !reexecing {
				logger.Info("Shutting down Elastic Agent and sending last events...")
			} else {
				logger.Info("Restarting Elastic Agent")
>>>>>>> 567f9e2dce (Improve shutdown logs (#1618) (#1627))
			}
		}
	}

	if logShutdown {
		logger.Info("Shutting down Elastic Agent and sending last events...")
	}
	cancel()
	err = <-appErr

	if logShutdown {
		logger.Info("Shutting down completed.")
	}
	if isRex {
		rex.ShutdownComplete()
	}
	return err
}

func loadConfig(override cfgOverrider) (*configuration.Configuration, error) {
	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	if err := getOverwrites(rawConfig); err != nil {
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

func getOverwrites(rawConfig *config.Config) error {
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return err
	}

	if !cfg.Fleet.Enabled {
		// overrides should apply only for fleet mode
		return nil
	}
	path := paths.AgentConfigFile()
	store := storage.NewEncryptedDiskStore(path)

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

func defaultLogLevel(cfg *configuration.Configuration) string {
	if configuration.IsStandalone(cfg.Fleet) {
		// for standalone always take the one from config and don't override
		return ""
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
	return loadConfig(override)
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
