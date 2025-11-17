// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.elastic.co/apm/v2"

	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"

	"github.com/elastic/go-ucfg"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/dispatcher"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	stateStore "github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetes"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/fleet"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/lazy"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/retrier"
	fleetclient "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	otelconfig "github.com/elastic/elastic-agent/internal/pkg/otel/config"
	otelmanager "github.com/elastic/elastic-agent/internal/pkg/otel/manager"
	"github.com/elastic/elastic-agent/internal/pkg/queue"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/limits"
	"github.com/elastic/elastic-agent/version"
)

type rollbacksSource interface {
	Set(map[string]ttl.TTLMarker) error
	Get() (map[string]ttl.TTLMarker, error)
}

// CfgOverrider allows for application driven overrides of configuration read from disk.
type CfgOverrider func(cfg *configuration.Configuration)

// New creates a new Agent and bootstrap the required subsystem.
func New(
	ctx context.Context,
	log *logger.Logger,
	baseLogger *logger.Logger,
	logLevel logp.Level,
	agentInfo info.Agent,
	reexec coordinator.ReExecManager,
	tracer *apm.Tracer,
	testingMode bool,
	fleetInitTimeout time.Duration,
	disableMonitoring bool,
	override CfgOverrider,
	initialUpdateMarker *upgrade.UpdateMarker,
	modifiers ...component.PlatformModifier,
) (*coordinator.Coordinator, coordinator.ConfigManager, composable.Controller, error) {

	err := version.InitVersionError()
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
		log.Infof("Loading baseline config from %v", pathConfigFile)
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

	if override != nil {
		override(cfg)
	}

	// monitoring is not supported in bootstrap mode https://github.com/elastic/elastic-agent/issues/1761
	isMonitoringSupported := !disableMonitoring && cfg.Settings.V1MonitoringEnabled

	availableRollbacksSource := ttl.NewTTLMarkerRegistry(log, paths.Top())
	if upgrade.IsUpgradeable() {
		// If we are not running in a container, check and normalize the install descriptor before we start the agent
		normalizeAgentInstalls(log, paths.Top(), time.Now(), initialUpdateMarker, availableRollbacksSource)
	}
	upgrader, err := upgrade.NewUpgrader(log, cfg.Settings.DownloadConfig, cfg.Settings.Upgrade, agentInfo, new(upgrade.AgentWatcherHelper), availableRollbacksSource)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create upgrader: %w", err)
	}
	monitor := componentmonitoring.New(
		isMonitoringSupported,
		cfg.Settings.DownloadConfig.OS(),
		cfg.Settings.MonitoringConfig,
		agentInfo,
		log,
	)

	runtime, err := runtime.NewManager(
		log,
		baseLogger,
		agentInfo,
		tracer,
		monitor,
		cfg.Settings.GRPC,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
	}

	// prepare initialUpgradeDetails for injecting it in coordinator later on
	var initialUpgradeDetails *details.Details
	if initialUpdateMarker != nil && initialUpdateMarker.Details != nil {
		initialUpgradeDetails = initialUpdateMarker.Details
	}

	var configMgr coordinator.ConfigManager
	var managed *managedConfigManager
	var compModifiers = []component.ComponentsModifier{InjectAPMConfig}
	var composableManaged bool
	var isManaged bool
	var actionAcker acker.Acker
	if testingMode {
		log.Info("Elastic Agent has been started in testing mode and is managed through the control protocol")

		// testing mode uses a config manager that takes configuration from over the control protocol
		configMgr = newTestingModeConfigManager(log)
	} else if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Parsed configuration and determined agent is managed locally")

		loader := config.NewLoader(log, paths.ExternalInputs())
		rawCfgMap, err := rawConfig.ToMapStr()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to transform agent configuration into a map: %w", err)
		}
		discover := config.Discoverer(pathConfigFile, cfg.Settings.Path, paths.ExternalInputs(),
			kubernetes.GetHintsInputConfigPath(log, rawCfgMap))
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
		store, cfg, err = mergeFleetConfig(ctx, rawConfig)
		if err != nil {
			return nil, nil, nil, err
		}
		if configuration.IsFleetServerBootstrap(cfg.Fleet) {
			log.Info("Parsed configuration and determined agent is in Fleet Server bootstrap mode")

			compModifiers = append(compModifiers, FleetServerComponentModifier(cfg.Fleet.Server))
			configMgr = coordinator.NewConfigPatchManager(newFleetServerBootstrapManager(log), PatchAPMConfig(log, rawConfig))
		} else {
			log.Info("Parsed configuration and determined agent is managed by Fleet")

			composableManaged = true
			compModifiers = append(compModifiers,
				FleetServerComponentModifier(cfg.Fleet.Server),
				InjectFleetConfigComponentModifier(cfg.Fleet, agentInfo),
				EndpointSignedComponentModifier(),
				EndpointTLSComponentModifier(log),
				InjectProxyEndpointModifier(),
			)

			client, err := fleetclient.NewAuthWithConfig(log, cfg.Fleet.AccessAPIKey, cfg.Fleet.Client)
			if err != nil {
				return nil, nil, nil, errors.New(err,
					"fail to create API client",
					errors.TypeNetwork,
					errors.M(errors.MetaKeyURI, cfg.Fleet.Client.Host))
			}
			stateStorage, err := stateStore.NewStateStoreWithMigration(ctx, log, paths.AgentActionStoreFile(), paths.AgentStateStoreFile())
			if err != nil {
				return nil, nil, nil, errors.New(err, fmt.Sprintf("fail to read state store '%s'", paths.AgentStateStoreFile()))
			}

			fleetAcker, err := fleet.NewAcker(log, agentInfo, client)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to create acker: %w", err)
			}

			retrier := retrier.New(fleetAcker, log)
			batchedAcker := lazy.NewAcker(fleetAcker, log, lazy.WithRetrier(retrier))
			actionAcker = stateStore.NewStateStoreActionAcker(batchedAcker, stateStorage)

			actionQueue, err := queue.NewActionQueue(stateStorage.Queue(), stateStorage)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("unable to initialize action queue: %w", err)
			}

			if initialUpgradeDetails == nil {
				// initial upgrade details  are nil (normally the caller supplies the ones from the marker file at this point),
				// hence, extract any scheduled upgrade details from the action queue.
				initialUpgradeDetails = dispatcher.GetScheduledUpgradeDetails(log, actionQueue.Actions(), time.Now())
			}

			// TODO: stop using global state
			managed, err = newManagedConfigManager(ctx, log, agentInfo, cfg, store, runtime, fleetInitTimeout, paths.Top(), client, fleetAcker, actionAcker, retrier, stateStorage, actionQueue, availableRollbacksSource, upgrader)
			if err != nil {
				return nil, nil, nil, err
			}
			configMgr = coordinator.NewConfigPatchManager(managed, injectOutputOverrides(log, rawConfig), PatchAPMConfig(log, rawConfig))
		}
	}

	varsManager, err := composable.New(log, rawConfig, composableManaged)
	if err != nil {
		return nil, nil, nil, errors.New(err, "failed to initialize composable controller")
	}

	otelManager, err := otelmanager.NewOTelManager(
		log.Named("otel_manager"),
		logLevel, baseLogger,
		otelconfig.SubprocessExecutionMode,
		agentInfo,
		cfg.Settings.Collector,
		monitor.ComponentMonitoringConfig,
		otelmanager.CollectorStopTimeout,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create otel manager: %w", err)
	}
	coord := coordinator.New(log, cfg, logLevel, agentInfo, specs, reexec, upgrader, runtime, configMgr, varsManager, caps, monitor, isManaged, otelManager, actionAcker, initialUpgradeDetails, compModifiers...)
	if managed != nil {
		// the coordinator requires the config manager as well as in managed-mode the config manager requires the
		// coordinator, so it must be set here once the coordinator is created
		managed.coord = coord
	}

	// every time we change the limits we'll see the log message
	limits.AddLimitsOnChangeCallback(func(new, old limits.LimitsConfig) {
		log.Debugf("agent limits have changed: %+v -> %+v", old, new)
	}, "application.go")
	// applying the initial limits for the agent process
	if err := limits.Apply(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse and apply limits config: %w", err)
	}

	// It is important that feature flags from configuration are applied as late as possible.  This will ensure that
	// any feature flag change callbacks are registered before they get called by `features.Apply`.
	if err := features.Apply(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse and apply feature flags config: %w", err)
	}

	return coord, configMgr, varsManager, nil
}

// normalizeAgentInstalls will attempt to normalize the agent installs and related TTL markers:
// - if we just rolled back: the update marker is checked and in case of rollback we clean up the TTL marker of the rolled back version
// - check all the entries:
//   - verify that the home directory for that install still exists (remove TTL markers for what does not exist anymore)
//   - check if the agent install: if it is no longer valid collect the versioned home and the TTL marker for deletion
//
// This function will NOT error out, it will log any errors it encounters as warnings but any error must be treated as non-fatal
func normalizeAgentInstalls(log *logger.Logger, topDir string, now time.Time, initialUpdateMarker *upgrade.UpdateMarker, rollbackSource rollbacksSource) {
	// Check if we rolled back and update the TTL markers
	if initialUpdateMarker != nil && initialUpdateMarker.Details != nil && initialUpdateMarker.Details.State == details.StateRollback {
		// Reset the TTL for the current version if we are coming off a rollback
		rollbacks, err := rollbackSource.Get()
		if err != nil {
			log.Warnf("Error getting available rollbacks from rollbackSource during startup check: %s", err)
			return
		}

		// remove the current versioned home TTL marker
		delete(rollbacks, initialUpdateMarker.PrevVersionedHome)
		err = rollbackSource.Set(rollbacks)
		if err != nil {
			log.Warnf("Error setting available rollbacks during normalization: %s", err)
			return
		}
	}

	// check if we need to cleanup old agent installs
	rollbacks, err := rollbackSource.Get()
	if err != nil {
		log.Warnf("Error getting available rollbacks during startup check: %s", err)
		return
	}

	var versionedHomesToCleanup []string
	for versionedHome, ttlMarker := range rollbacks {

		versionedHomeAbsPath := filepath.Join(topDir, versionedHome)

		if versionedHomeAbsPath == paths.HomeFrom(topDir) {
			// skip the current install
			log.Warnf("Found a TTL marker for the currently running agent at %s. Skipping cleanup...", versionedHome)
			continue
		}

		_, err = os.Stat(versionedHomeAbsPath)
		if errors.Is(err, os.ErrNotExist) {
			log.Warnf("Versioned home %s corresponding to agent TTL marker %+v  is not found on disk", versionedHomeAbsPath, ttlMarker)
			versionedHomesToCleanup = append(versionedHomesToCleanup, versionedHome)
			continue
		}

		if err != nil {
			log.Warnf("error checking versioned home %s for agent install: %s", versionedHomeAbsPath, err.Error())
			continue
		}

		if now.After(ttlMarker.ValidUntil) {
			// the install directory exists but it's expired. Remove the files.
			log.Infof("agent TTL marker %+v marks %q as expired, removing directory", ttlMarker, versionedHomeAbsPath)
			if cleanupErr := install.RemoveBut(versionedHomeAbsPath, true); cleanupErr != nil {
				log.Warnf("Error removing directory %q: %s", versionedHomeAbsPath, cleanupErr)
			} else {
				log.Infof("Directory %q was removed", versionedHomeAbsPath)
				versionedHomesToCleanup = append(versionedHomesToCleanup, versionedHome)
			}
		}
	}

	if len(versionedHomesToCleanup) > 0 {
		log.Infof("removing install descriptor(s) for %v", versionedHomesToCleanup)
		for _, versionedHomeToCleanup := range versionedHomesToCleanup {
			delete(rollbacks, versionedHomeToCleanup)
		}
		err = rollbackSource.Set(rollbacks)
		if err != nil {
			log.Warnf("Error removing install descriptor(s): %s", err)
		}
	}
}

func mergeFleetConfig(ctx context.Context, rawConfig *config.Config) (storage.Store, *configuration.Configuration, error) {
	path := paths.AgentConfigFile()
	store, err := storage.NewEncryptedDiskStore(ctx, path)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating encrypted disk store: %w", err)
	}

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

// injectOutputOverrides takes local configuration for specific outputs and applies them to the configuration.
//
// The name of the output must match or no options will be overwritten.
func injectOutputOverrides(log *logger.Logger, rawConfig *config.Config) func(change coordinator.ConfigChange) coordinator.ConfigChange {
	// merging uses no resolving as the AST variable substitution occurs on the outputs
	// append the values to arrays (don't allow complete overriding of arrays)
	mergeOpts := config.NoResolveOptions
	mergeOpts = append(mergeOpts, ucfg.AppendValues)

	// parse the outputs defined local in the configuration
	// in the case the configuration as no outputs defined (most cases) then noop can be used
	var parsed struct {
		Outputs map[string]*ucfg.Config `config:"outputs"`
	}
	err := rawConfig.UnpackTo(&parsed)
	if err != nil {
		log.Errorf("error decoding raw config, output injection disabled: %v", err)
		return noop
	}
	if len(parsed.Outputs) == 0 {
		return noop
	}

	return func(change coordinator.ConfigChange) coordinator.ConfigChange {
		cfg := change.Config()
		outputs, err := cfg.Agent.Child("outputs", -1)
		if err != nil {
			if !isMissingError(err) {
				// expecting only ErrMissing
				log.Errorf("error getting outputs from config: %v", err)
			}
			return change
		}
		for outputName, outputOverrides := range parsed.Outputs {
			cfgOutput, err := outputs.Child(outputName, -1)
			if err != nil {
				// no output with that name; do nothing
				continue
			}
			// the order of merging is important
			//
			// this merges the ConfigChange on-top of the rawConfig to ensure that the
			// ConfigChange options always override local options
			//
			// meaning that local options are only applied in the case that the ConfigChange
			// doesn't provide a different value for those fields
			err = func() error {
				clone, err := ucfg.NewFrom(outputOverrides, mergeOpts...)
				if err != nil {
					return fmt.Errorf("failed to clone output overrides: %w", err)
				}
				err = clone.Merge(cfgOutput, mergeOpts...)
				if err != nil {
					return fmt.Errorf("failed to merge output over overrides: %w", err)
				}
				err = outputs.SetChild(outputName, -1, clone, mergeOpts...)
				if err != nil {
					return fmt.Errorf("failed to re-set output with overrides: %w", err)
				}
				return nil
			}()
			if err != nil {
				log.Errorf("failed to perform output injection for output %s: %v", outputName, err)
				continue
			}
			log.Infof("successfully injected output overrides for output %s", outputName)
		}
		return change
	}
}

// isMissingError returns true if the error is because the field is missing
//
// Sadly go-ucfg doesn't support Unwrap interface so using `errors.Is(err, ucfg.ErrMissing)` doesn't work
// this specific function is required to ensure its an `ErrMissing` error.
func isMissingError(err error) bool {
	//nolint:errorlint // limitation of go-ucfg (read docstring)
	switch v := err.(type) {
	case ucfg.Error:
		//nolint:errorlint // limitation of go-ucfg (read docstring)
		return v.Reason() == ucfg.ErrMissing
	}
	return false
}
