// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.elastic.co/apm/v2"
	apmtransport "go.elastic.co/apm/v2/transport"
	"gopkg.in/yaml.v2"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/logp"
	monitoringLib "github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent-libs/service"
	"github.com/elastic/elastic-agent-system-metrics/report"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/reload"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
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
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/elastic/elastic-agent/version"
)

const (
	agentName            = "elastic-agent"
	fleetInitTimeoutName = "FLEET_SERVER_INIT_TIMEOUT"
	flagRunDevelopment   = "develop"
)

type (
	cfgOverrider func(cfg *configuration.Configuration)
	awaiters     []<-chan struct{}
)

func newRunCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the Elastic Agent",
		Long:  "This command starts the Elastic Agent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			isDevelopmentMode, _ := cmd.Flags().GetBool(flagInstallDevelopment)
			if isDevelopmentMode {
				fmt.Fprintln(streams.Out, "Development installation mode enabled; this is an experimental feature.")
				// For now, development mode only makes the agent behave as if it was running in a namespace to allow
				// multiple agents on the same machine.
				paths.SetInstallNamespace(paths.DevelopmentNamespace)
			}

			// done very early so the encrypted store is never used. Always done in development mode to remove the need to be root.
			disableEncryptedStore, _ := cmd.Flags().GetBool("disable-encrypted-store")
			if disableEncryptedStore || isDevelopmentMode {
				storage.DisableEncryptionDarwin()
			}
			fleetInitTimeout, _ := cmd.Flags().GetDuration("fleet-init-timeout")
			testingMode, _ := cmd.Flags().GetBool("testing-mode")
			if err := run(nil, testingMode, fleetInitTimeout); err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				logExternal(fmt.Sprintf("%s run failed: %s", paths.BinaryName, err))
				return err
			}
			return nil
		},
	}

	// --disable-encrypted-store only has meaning on Mac OS, and it disables the encrypted disk store
	// feature of the Elastic Agent. On Mac OS root privileges are required to perform the disk
	// store encryption, by setting this flag it disables that feature and allows the Elastic Agent to
	// run as non-root.
	//
	// Deprecated: MacOS can be run/installed without root privileges
	cmd.Flags().Bool("disable-encrypted-store", false, "Disable the encrypted disk storage (Only useful on Mac OS)")
	_ = cmd.Flags().MarkHidden("disable-encrypted-store")
	_ = cmd.Flags().MarkDeprecated("disable-encrypted-store", "agent on Mac OS can be run/installed without root privileges, see elastic-agent install --help")

	// --testing-mode is a hidden flag that spawns the Elastic Agent in testing mode
	// it is hidden because we really don't want users to execute Elastic Agent to run
	// this way, only the integration testing framework runs the Elastic Agent in this mode
	cmd.Flags().Bool("testing-mode", false, "Run with testing mode enabled")

	cmd.Flags().Duration("fleet-init-timeout", envTimeout(fleetInitTimeoutName), " Sets the initial timeout when starting up the fleet server under agent")
	_ = cmd.Flags().MarkHidden("testing-mode")

	cmd.Flags().Bool(flagRunDevelopment, false, "Run agent in development mode. Allows running when there is already an installed Elastic Agent. (experimental)")
	_ = cmd.Flags().MarkHidden(flagRunDevelopment) // For internal use only.

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
	stopBeat := func() {
		close(stop)
	}

	defer cancel()
	go service.ProcessWindowsControlEvents(stopBeat)

	return runElasticAgent(ctx, cancel, override, stop, testingMode, fleetInitTimeout, false, nil, modifiers...)
}

func logReturn(l *logger.Logger, err error) error {
	if err != nil && !errors.Is(err, context.Canceled) {
		l.Errorf("%s", err)
	}
	return err
}

func runElasticAgent(ctx context.Context, cancel context.CancelFunc, override cfgOverrider, stop chan bool, testingMode bool, fleetInitTimeout time.Duration, runAsOtel bool, awaiters awaiters, modifiers ...component.PlatformModifier) error {
	cfg, err := loadConfig(ctx, override, runAsOtel)
	if err != nil {
		return err
	}

	logLvl := logger.DefaultLogLevel
	if cfg.Settings.LoggingConfig != nil {
		logLvl = cfg.Settings.LoggingConfig.Level
	}
	baseLogger, err := logger.NewFromConfig("", cfg.Settings.LoggingConfig, cfg.Settings.EventLoggingConfig, true)
	if err != nil {
		return err
	}

	// Make sure to flush any buffered logs before we're done.
	defer baseLogger.Sync() //nolint:errcheck // flushing buffered logs is best effort.

	l := baseLogger.With("log", map[string]interface{}{
		"source": agentName,
	})

	// try early to check if running as root
	isRoot, err := utils.HasRoot()
	if err != nil {
		return logReturn(l, fmt.Errorf("failed to check for root/Administrator privileges: %w", err))
	}

	l.Infow("Elastic Agent started",
		"process.pid", os.Getpid(),
		"agent.version", version.GetAgentPackageVersion(),
		"agent.unprivileged", !isRoot)

	cfg, err = tryDelayEnroll(ctx, l, cfg, override)
	if err != nil {
		return logReturn(l, errors.New(err, "failed to perform delayed enrollment"))
	}
	pathConfigFile := paths.AgentConfigFile()

	// agent ID needs to stay empty in bootstrap mode
	createAgentID := !runAsOtel
	if cfg.Fleet != nil && cfg.Fleet.Server != nil && cfg.Fleet.Server.Bootstrap {
		createAgentID = false
	}

	// Ensure we have the agent secret created.
	// The secret is not created here if it exists already from the previous enrollment.
	// This is needed for compatibility with agent running in standalone mode,
	// that writes the agentID into fleet.enc (encrypted fleet.yml) before even loading the configuration.
	err = secret.CreateAgentSecret(ctx, vault.WithUnprivileged(!isRoot))
	if err != nil {
		return logReturn(l, fmt.Errorf("failed to read/write secrets: %w", err))
	}

	// Migrate .yml files if the corresponding .enc does not exist

	// the encrypted config does not exist but the unencrypted file does
	err = migration.MigrateToEncryptedConfig(ctx, l, paths.AgentConfigYmlFile(), paths.AgentConfigFile())
	if err != nil {
		return logReturn(l, errors.New(err, "error migrating fleet config"))
	}

	// the encrypted state does not exist but the unencrypted file does
	err = migration.MigrateToEncryptedConfig(ctx, l,
		paths.AgentStateStoreYmlFile(),
		paths.AgentStateStoreFile())
	if err != nil {
		return logReturn(l, errors.New(err, "error migrating agent state"))
	}

	agentInfo, err := info.NewAgentInfoWithLog(ctx, defaultLogLevel(cfg, logLvl.String()), createAgentID)
	if err != nil {
		return logReturn(l, errors.New(err,
			"could not load agent info",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile)))
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
	} else {
		// Set the initial log level (either default or from config file)
		logger.SetLevel(logLvl)
	}

	// initiate agent watcher
	if _, err := upgrade.InvokeWatcher(l, paths.TopBinaryPath()); err != nil {
		// we should not fail because watcher is not working
		l.Error(errors.New(err, "failed to invoke rollback watcher"))
	}

	execPath, err := reexecPath()
	if err != nil {
		return logReturn(l, fmt.Errorf("failed to get reexec path: %w", err))
	}
	rexLogger := l.Named("reexec")
	rex := reexec.NewManager(rexLogger, execPath)

	tracer, err := initTracer(agentName, release.Version(), cfg.Settings.MonitoringConfig)
	if err != nil {
		return logReturn(l, fmt.Errorf("could not initiate APM tracer: %w", err))
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

	coord, configMgr, composable, err := application.New(ctx, l, baseLogger, logLvl, agentInfo, rex, tracer, testingMode, fleetInitTimeout, configuration.IsFleetServerBootstrap(cfg.Fleet), runAsOtel, modifiers...)
	if err != nil {
		return logReturn(l, err)
	}
	defer func() {
		if composable != nil {
			composable.Close()
		}
	}()

	monitoringServer, err := setupMetrics(l, cfg.Settings.DownloadConfig.OS(), cfg.Settings.MonitoringConfig, tracer, coord)
	if err != nil {
		return logReturn(l, err)
	}
	coord.RegisterMonitoringServer(monitoringServer)
	defer func() {
		if monitoringServer != nil {
			_ = monitoringServer.Stop()
		}
	}()

	diagHooks := diagnostics.GlobalHooks()
	diagHooks = append(diagHooks, coord.DiagnosticHooks()...)
	controlLog := l.Named("control")
	control := server.New(controlLog, agentInfo, coord, tracer, diagHooks, cfg.Settings.GRPC)

	// if the configMgr implements the TestModeConfigSetter in means that Elastic Agent is in testing mode and
	// the configuration will come in over the control protocol, so we set the config setting on the control protocol
	// server so when the configuration comes in it gets passed to the coordinator
	testingSetter, ok := configMgr.(server.TestModeConfigSetter)
	if ok {
		control.SetTestModeConfigSetter(testingSetter)
	}

	// start the control listener
	if err := control.Start(); err != nil {
		return logReturn(l, err)
	}
	defer control.Stop()

	// create symlink from /run/elastic-agent.sock to `paths.ControlSocket()` when running as root
	// this provides backwards compatibility as the control socket was moved with the addition of --unprivileged
	// option during installation
	//
	// Windows `paths.ControlSocketRunSymlink()` is `""` so this is always skipped on Windows.
	controlSocketRunSymlink := paths.ControlSocketRunSymlink(paths.InstallNamespace())
	if isRoot && paths.RunningInstalled() && controlSocketRunSymlink != "" {
		socketPath := strings.TrimPrefix(paths.ControlSocket(), "unix://")
		socketLog := controlLog.With("path", socketPath).With("link", controlSocketRunSymlink)
		// ensure it doesn't exist before creating the symlink
		if err := os.Remove(controlSocketRunSymlink); err != nil && !errors.Is(err, os.ErrNotExist) {
			socketLog.Errorf("Failed to remove existing control socket symlink %s: %s", controlSocketRunSymlink, err)
		}
		if err := os.Symlink(socketPath, controlSocketRunSymlink); err != nil {
			socketLog.Errorf("Failed to create control socket symlink %s -> %s: %s", controlSocketRunSymlink, socketPath, err)
		} else {
			socketLog.Infof("Created control socket symlink %s -> %s; allowing unix://%s connection", controlSocketRunSymlink, socketPath, controlSocketRunSymlink)
		}
		defer func() {
			// delete the symlink on exit; ignore the error
			if err := os.Remove(controlSocketRunSymlink); err != nil {
				socketLog.Errorf("Failed to remove control socket symlink %s: %s", controlSocketRunSymlink, err)
			}
		}()
	}

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
	for _, a := range awaiters {
		<-a // wait for awaiter to be done
	}

	if logShutdown {
		l.Info("Shutting down completed.")
	}
	if isRex {
		rex.ShutdownComplete()
	}
	return logReturn(l, err)
}

func loadConfig(ctx context.Context, override cfgOverrider, runAsOtel bool) (*configuration.Configuration, error) {
	if runAsOtel {
		defaultCfg := configuration.DefaultConfiguration()
		// disable monitoring to avoid injection of monitoring components
		// in case inputs are not empty
		defaultCfg.Settings.MonitoringConfig.Enabled = false
		defaultCfg.Settings.V1MonitoringEnabled = false
		return defaultCfg, nil
	}

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
	store, err := storage.NewEncryptedDiskStore(ctx, path)
	if err != nil {
		return fmt.Errorf("error instantiating encrypted disk store: %w", err)
	}

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

	return ""
}

func tryDelayEnroll(ctx context.Context, logger *logger.Logger, cfg *configuration.Configuration, override cfgOverrider) (*configuration.Configuration, error) {
	enrollPath := paths.AgentEnrollFile()
	if _, err := os.Stat(enrollPath); err != nil {
		//nolint:nilerr // ignore the error, this is expected
		// no enrollment file exists or failed to stat it; nothing to do
		return cfg, nil
	}
	contents, err := os.ReadFile(enrollPath)
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
	// enrollCmd daemonReloadWithBackoff is broken
	// see https://github.com/elastic/elastic-agent/issues/4043
	// SkipDaemonRestart to true avoids running that code.
	options.SkipDaemonRestart = true
	pathConfigFile := paths.ConfigFile()
	encStore, err := storage.NewEncryptedDiskStore(ctx, paths.AgentConfigFile())
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted disk store: %w", err)
	}
	store := storage.NewReplaceOnSuccessStore(
		pathConfigFile,
		application.DefaultAgentFleetConfig,
		encStore,
	)
	c, err := newEnrollCmd(
		logger,
		&options,
		paths.ConfigFile(),
		store,
	)
	if err != nil {
		return nil, err
	}
	// perform the enrollment in a loop, it should keep trying to enroll no matter what
	// the enrollCmd has built in backoff so no need to wrap this in its own backoff as well
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		err = c.Execute(ctx, cli.NewIOStreams())
		if err == nil {
			// enrollment was successful
			break
		}
		logger.Error(fmt.Errorf("failed to perform delayed enrollment (will try again): %w", err))
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
	return loadConfig(ctx, override, false)
}

func initTracer(agentName, version string, mcfg *monitoringCfg.MonitoringConfig) (*apm.Tracer, error) {
	apm.DefaultTracer().Close()

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

	opts := apmtransport.HTTPTransportOptions{}

	if len(cfg.Hosts) > 0 {
		hosts := make([]*url.URL, 0, len(cfg.Hosts))
		for _, host := range cfg.Hosts {
			u, err := url.Parse(host)
			if err != nil {
				return nil, fmt.Errorf("failed parsing %s: %w", host, err)
			}
			hosts = append(hosts, u)
		}
		opts.ServerURLs = hosts
	}
	if cfg.APIKey != "" {
		opts.APIKey = cfg.APIKey
	} else {
		opts.SecretToken = cfg.SecretToken
	}

	ts, err := apmtransport.NewHTTPTransport(opts)
	if err != nil {
		return nil, err
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
) (*reload.ServerReloader, error) {
	if err := report.SetupMetrics(logger, agentName, version.GetDefaultVersion()); err != nil {
		return nil, err
	}

	// start server for stats
	endpointConfig := api.Config{
		Enabled: true,
		Host:    monitoring.AgentMonitoringEndpoint(operatingSystem, cfg),
	}

	s, err := monitoring.NewServer(logger, endpointConfig, monitoringLib.GetNamespace, tracer, coord, operatingSystem, cfg)
	if err != nil {
		return nil, errors.New(err, "could not start the HTTP server for the API")
	}

	return s, nil
}

// handleUpgrade checks if agent is being run as part of an
// ongoing upgrade operation, i.e. being re-exec'd and performs
// any upgrade-specific work, if needed.
func handleUpgrade() error {
	upgradeMarker, err := upgrade.LoadMarker(paths.Data())
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
	if paths.RunningInstalled() {
		return nil
	}

	// Otherwise, we're being upgraded from a version of an installed Agent
	// that didn't use an installation marker file (that is, before v8.8.0).
	// So create the file now.
	ownership, err := utils.CurrentFileOwner()
	if err != nil {
		return fmt.Errorf("failed to get current file owner: %w", err)
	}
	if err := install.CreateInstallMarker(paths.Top(), ownership); err != nil {
		return fmt.Errorf("unable to create installation marker file during upgrade: %w", err)
	}

	// In v8.14.0, the control socket was moved to be in the installation path instead at
	// a system level location, except on Windows where it remained at `npipe:///elastic-agent-system`.
	// For Windows to be able to determine if it is running installed is from the creation of
	// `.installed` marker that was not created until v8.8.0. Upgrading from any pre-8.8 version results
	// in the `paths.ControlSocket()` in returning the incorrect control socket (only on Windows).
	// Now that the install marker has been created we need to ensure that `paths.ControlSocket()` will
	// return the correct result.
	// We are being upgraded, we're running as installed, marker was just created.
	paths.ResolveControlSocket(true)

	return nil
}
