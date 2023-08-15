// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"fmt"
	"os"
	"time"

	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/features"
	operatorv1alpha1 "github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
	"github.com/elastic/elastic-agent/pkg/operator/controllers"
	"github.com/elastic/elastic-agent/version"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/env"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// New creates a new Agent and bootstrap the required subsystem.
func New(
	log *logger.Logger,
	baseLogger *logger.Logger,
	logLevel logp.Level,
	agentInfo *info.AgentInfo,
	reexec coordinator.ReExecManager,
	tracer *apm.Tracer,
	testingMode bool,
	fleetInitTimeout time.Duration,
	disableMonitoring bool,
	modifiers ...component.PlatformModifier,
) (*coordinator.Coordinator, coordinator.ConfigManager, composable.Controller, error) {

	log.Info("Running as operator")
	err := version.InitVersionInformation()
	if err != nil {
		// non-fatal error, log a warning and move on
		log.With("error.message", err).Warnf("Error initializing version information: falling back to %s", release.Version())
	}

	platform, err := component.LoadPlatformDetail(modifiers...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to gather system information: %w", err)
	}
	log.Info("Gathered system information")

	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}
	log.With("inputs", specs.Inputs()).Info("Detected available inputs and outputs")

	caps, err := capabilities.LoadFile(paths.AgentCapabilitiesPath(), log)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to determine capabilities: %w", err)
	}
	log.Info("Determined allowed capabilities")

	pathConfigFile := paths.ConfigFile()

	var rawConfig *config.Config
	if testingMode {
		// testing mode doesn't read any configuration from the disk
		rawConfig, err = config.NewConfigFrom("")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
		}

		// monitoring is always disabled in testing mode
		disableMonitoring = true
	} else {
		rawConfig, err = config.LoadFile(pathConfigFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
		}
	}
	if err := info.InjectAgentConfig(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// monitoring is not supported in bootstrap mode https://github.com/elastic/elastic-agent/issues/1761
	isMonitoringSupported := !disableMonitoring && cfg.Settings.V1MonitoringEnabled
	upgrader := upgrade.NewUpgrader(log, cfg.Settings.DownloadConfig, agentInfo)
	monitor := monitoring.New(isMonitoringSupported, cfg.Settings.DownloadConfig.OS(), cfg.Settings.MonitoringConfig, agentInfo)

	var runtimeMgr coordinator.RuntimeManager
	if isOperator() {
		log.Info("Acting as operator creating runtime mgr")
		runtimeMgr, err = runtime.NewOperatorManager(
			log,
			baseLogger,
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
		}
	} else {
		runtimeMgr, err = runtime.NewManager(
			log,
			baseLogger,
			cfg.Settings.GRPC.String(),
			agentInfo,
			tracer,
			monitor,
			cfg.Settings.GRPC,
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
		}
	}

	var configMgr coordinator.ConfigManager
	var managed *managedConfigManager
	var compModifiers []coordinator.ComponentsModifier
	var composableManaged bool
	var isManaged bool
	if testingMode {
		log.Info("Elastic Agent has been started in testing mode and is managed through the control protocol")

		// testing mode uses a config manager that takes configuration from over the control protocol
		configMgr = newTestingModeConfigManager(log)
	} else if isOperator() {
		log.Info("Acting as operator creating setting up config mgr")
		runtimeWatcher, ok := runtimeMgr.(controllers.Watcher)
		if !ok {
			panic("runtime manager does not implement controllers.Watcher")
		}
		configMgr = registerOperatorWatches(log, runtimeWatcher)
	} else if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Parsed configuration and determined agent is managed locally")

		loader := config.NewLoader(log, paths.ExternalInputs())
		discover := config.Discoverer(pathConfigFile, cfg.Settings.Path, paths.ExternalInputs())
		if !cfg.Settings.Reload.Enabled {
			log.Debug("Reloading of configuration is off")
			configMgr = newOnce(log, discover, loader)
		} else {
			log.Debugf("Reloading of configuration is on, frequency is set to %s", cfg.Settings.Reload.Period)
			configMgr = newPeriodic(log, cfg.Settings.Reload.Period, discover, loader)
		}
	} else {
		isManaged = true
		var store storage.Store
		store, cfg, err = mergeFleetConfig(rawConfig)
		if err != nil {
			return nil, nil, nil, err
		}

		if configuration.IsFleetServerBootstrap(cfg.Fleet) {
			log.Info("Parsed configuration and determined agent is in Fleet Server bootstrap mode")

			compModifiers = append(compModifiers, FleetServerComponentModifier(cfg.Fleet.Server))
			configMgr = newFleetServerBootstrapManager(log)
		} else {
			log.Info("Parsed configuration and determined agent is managed by Fleet")

			composableManaged = true
			compModifiers = append(compModifiers, FleetServerComponentModifier(cfg.Fleet.Server),
				InjectFleetConfigComponentModifier(cfg.Fleet, agentInfo),
				EndpointSignedComponentModifier(),
			)

			managed, err = newManagedConfigManager(log, agentInfo, cfg, store, runtimeMgr, fleetInitTimeout)
			if err != nil {
				return nil, nil, nil, err
			}
			configMgr = managed
		}
	}

	composable, err := composable.New(log, rawConfig, composableManaged)
	if err != nil {
		return nil, nil, nil, errors.New(err, "failed to initialize composable controller")
	}

	coord := coordinator.New(log, cfg, logLevel, agentInfo, specs, reexec, upgrader, runtimeMgr, configMgr, composable, caps, monitor, isManaged, compModifiers...)
	if managed != nil {
		// the coordinator requires the config manager as well as in managed-mode the config manager requires the
		// coordinator, so it must be set here once the coordinator is created
		managed.coord = coord
	}

	// It is important that feature flags from configuration are applied as late as possible.  This will ensure that
	// any feature flag change callbacks are registered before they get called by `features.Apply`.
	if err := features.Apply(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse and apply feature flags config: %w", err)
	}

	return coord, configMgr, composable, nil
}

func mergeFleetConfig(rawConfig *config.Config) (storage.Store, *configuration.Configuration, error) {
	path := paths.AgentConfigFile()
	store := storage.NewEncryptedDiskStore(path)

	reader, err := store.Load()
	if err != nil {
		return store, nil, errors.New(err, "could not initialize config store",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}
	config, err := config.NewConfigFrom(reader)
	if err != nil {
		return store, nil, errors.New(err,
			fmt.Sprintf("fail to read configuration %s for the elastic-agent", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	// merge local configuration and configuration persisted from fleet.
	err = rawConfig.Merge(config)
	if err != nil {
		return store, nil, errors.New(err,
			fmt.Sprintf("fail to merge configuration with %s for the elastic-agent", path),
			errors.TypeConfig,
			errors.M(errors.MetaKeyPath, path))
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return store, nil, errors.New(err,
			fmt.Sprintf("fail to unpack configuration from %s", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	// Fix up fleet.agent.id otherwise the fleet.agent.id is empty string
	if cfg.Settings != nil && cfg.Fleet != nil && cfg.Fleet.Info != nil && cfg.Fleet.Info.ID == "" {
		cfg.Fleet.Info.ID = cfg.Settings.ID
	}

	if err := cfg.Fleet.Valid(); err != nil {
		return store, nil, errors.New(err,
			"fleet configuration is invalid",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	return store, cfg, nil
}

func registerOperatorWatches(log *logger.Logger, runtimeManager controllers.Watcher) coordinator.ConfigManager {
	scheme := k8sRuntime.NewScheme()
	setupLog := ctrl.Log.WithName("setup")
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(operatorv1alpha1.AddToScheme(scheme))

	var metricsAddr = env.WithDefault(":8080", "METRICS_BIND_ADDRESS")
	var probeAddr = env.WithDefault(":8081", "HEALTH_PROBE_BIND_ADDRESS")
	var enableLeaderElection = env.Bool("LEADER_ELECT")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "7aab3455.agent.k8s.elastic.co",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	var agentPolicyReconciler = controllers.NewElasticPolicyController(
		log,
		mgr.GetClient(),
		mgr.GetScheme(),
		runtimeManager,
	)
	if err = agentPolicyReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ElasticAgentPolicy")
		os.Exit(1)
	}

	var agentComponentReconciler = controllers.NewElasticComponentController(
		log,
		mgr.GetClient(),
		mgr.GetScheme(),
	)
	if err = (agentComponentReconciler).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ElasticAgentComponent")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	go func() {
		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	}()

	return agentPolicyReconciler.ConfigManager()
}

func isOperator() bool {
	return env.Bool("IS_OPERATOR")
}
