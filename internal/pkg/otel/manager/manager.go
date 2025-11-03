// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// OTelManager is a manager that manages the lifecycle of the OTel collector inside of the Elastic Agent.
type OTelManager struct {
	// baseLogger is the base logger for the otel collector, and doesn't include any agent-specific fields.
	baseLogger *logger.Logger
	logger     *logger.Logger
	errCh      chan error

	// The current configuration that the OTel collector is using. In the case that
	// the cfg is nil then the collector is not running.
	cfg *confmap.Conf

	// cfg is changed by sending its new value on cfgCh, where it is
	// handled by (*OTelManager).Run.
	cfgCh chan *confmap.Conf

	// stateCh passes the state information of the collector.
	statusCh chan *status.AggregateStatus

	// doneChan is closed when Run is stopped to signal that any
	// pending update calls should be ignored.
	doneChan chan struct{}
}

// NewOTelManager returns a OTelManager.
func NewOTelManager(logger, baseLogger *logger.Logger) *OTelManager {
	return &OTelManager{
		logger:     logger,
		baseLogger: baseLogger,
		errCh:      make(chan error, 1), // holds at most one error
		cfgCh:      make(chan *confmap.Conf),
		statusCh:   make(chan *status.AggregateStatus),
		doneChan:   make(chan struct{}),
	}
}

// Run runs the lifecycle of the manager.
func (m *OTelManager) Run(ctx context.Context) error {
	var err error
	var cancel context.CancelFunc
	var provider *agentprovider.Provider

<<<<<<< HEAD
	// signal that the run loop is ended to unblock any incoming update calls
	defer close(m.doneChan)

	runErrCh := make(chan error)
=======
	// collectorStatusCh is used internally by the otel collector to send status updates to the manager
	// this channel is buffered because it's possible for the collector to send a status update while the manager is
	// waiting for the collector to exit
	collectorStatusCh := make(chan *status.AggregateStatus, 1)
	forceFetchStatusCh := make(chan struct{}, 1)
>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
				<-runErrCh // wait for collector to be stopped
			}
			return ctx.Err()
<<<<<<< HEAD
		case err = <-runErrCh:
=======
		case <-m.recoveryTimer.C():
			m.recoveryTimer.Stop()

			if m.mergedCollectorCfg == nil || m.proc != nil || ctx.Err() != nil {
				// no configuration, or the collector is already running, or the context
				// is cancelled.
				continue
			}

			newRetries := m.recoveryRetries.Add(1)
			m.logger.Infof("collector recovery restarting, total retries: %d", newRetries)
			m.proc, err = m.execution.startCollector(ctx, m.baseLogger, m.logger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh, forceFetchStatusCh)
			if err != nil {
				reportErr(ctx, m.errCh, err)
				// reset the restart timer to the next backoff
				recoveryDelay := m.recoveryTimer.ResetNext()
				m.logger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
			} else {
				reportErr(ctx, m.errCh, nil)
			}

		case err = <-m.collectorRunErr:
			m.recoveryTimer.Stop()
>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
			if err == nil {
				// err is nil but there is a configuration
				//
				// in this rare case the collector stopped running but a configuration was
				// provided and the collector stopped with a clean exit
<<<<<<< HEAD
				cancel()
				cancel, provider, err = m.startCollector(m.cfg, runErrCh)
=======
				m.proc, err = m.execution.startCollector(ctx, m.baseLogger, m.logger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh, forceFetchStatusCh)
>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
				if err != nil {
					// failed to create the collector (this is different then
					// it's failing to run). we do not retry creation on failure
					// as it will always fail. A new configuration is required for
					// it not to fail (a new configuration will result in the retry)
					m.reportErr(ctx, err)
				} else {
					// all good at the moment (possible that it will fail)
					m.reportErr(ctx, nil)
				}
			} else {
				// error occurred while running the collector, this occurs in the
				// case that the configuration is invalid once the collector is started
				// or the context for running the collector is cancelled.
				//
				// in the case that the configuration is invalid there is no reason to
				// try again as it will keep failing so we do not trigger a restart
				if cancel != nil {
					cancel()
					cancel = nil
					provider = nil
					// don't wait here for <-runErrCh, already occurred
					// clear status, no longer running
					select {
					case m.statusCh <- nil:
					case <-ctx.Done():
					}
				}
				// pass the error to the errCh so the coordinator, unless it's a cancel error
				if !errors.Is(err, context.Canceled) {
					m.logger.Errorf("Failed to start the collector: %s", err)
					m.reportErr(ctx, err)
				}
			}
<<<<<<< HEAD
		case cfg := <-m.cfgCh:
			m.cfg = cfg
			if cfg == nil {
				// no configuration then the collector should not be
				// running. if a cancel exists then it is running
				// this cancels the context that will stop the running
				// collector (this configuration does not get passed
				// to the agent provider as an update)
				if cancel != nil {
					cancel()
					cancel = nil
					provider = nil
					<-runErrCh // wait for collector to be stopped
					// clear status, no longer running
					select {
					case m.statusCh <- nil:
					case <-ctx.Done():
					}
				}
				// ensure that the coordinator knows that there is no error
				// as the collector is not running anymore
				m.reportErr(ctx, nil)
			} else {
				// either a new configuration or the first configuration
				// that results in the collector being started
				if cancel == nil {
					// no cancel exists so the collector has not been
					// started. start the collector with this configuration
					cancel, provider, err = m.startCollector(m.cfg, runErrCh)
					if err != nil {
						// failed to create the collector (this is different then
						// it's failing to run). we do not retry creation on failure
						// as it will always fail. A new configuration is required for
						// it not to fail (a new configuration will result in the retry)
						m.reportErr(ctx, err)
					} else {
						// all good at the moment (possible that it will fail)
						m.reportErr(ctx, nil)
					}
				} else {
					// collector is already running so only the configuration
					// needs to be updated in the collector
					provider.Update(m.cfg)
				}
=======

		case cfgUpdate := <-m.updateCh:
			// we received a new configuration, thus stop the recovery timer
			// and reset the retry count
			m.recoveryTimer.Stop()
			m.recoveryRetries.Store(0)
			mergedCfg, err := buildMergedConfig(cfgUpdate, m.agentInfo, m.beatMonitoringConfigGetter, m.baseLogger)
			if err != nil {
				reportErr(ctx, m.errCh, err)
				continue
			}

			// this is the only place where we mutate the internal config attributes, take a write lock for the duration
			m.mx.Lock()
			previousConfigHash := m.mergedCollectorCfgHash
			configChanged, configUpdateErr := m.maybeUpdateMergedConfig(mergedCfg)
			m.collectorCfg = cfgUpdate.collectorCfg
			m.components = cfgUpdate.components
			m.mx.Unlock()

			if configUpdateErr != nil {
				m.logger.Warn("failed to calculate hash of merged config, proceeding with update", zap.Error(configUpdateErr))
			}

			if configChanged {
				m.logger.Debugf(
					"new config hash (%d) is different than the old config hash (%d), applying update",
					m.mergedCollectorCfgHash, previousConfigHash)
				applyErr := m.applyMergedConfig(ctx, collectorStatusCh, m.collectorRunErr, forceFetchStatusCh)
				// only report the error if we actually apply the update
				// otherwise, we could override an actual error with a nil in the channel when the collector
				// state doesn't actually change
				reportErr(ctx, m.errCh, applyErr)
			} else {
				m.logger.Debugf(
					"new config hash (%d) is identical to the old config hash (%d), skipping update",
					m.mergedCollectorCfgHash, previousConfigHash)

				// there was a config update, but the hash hasn't changed.
				// Force fetch the latest collector status in case the user modified the output.status_reporting flag.
				//
				// drain the channel first
				select {
				case <-forceFetchStatusCh:
				default:
				}
				forceFetchStatusCh <- struct{}{}
			}

		case otelStatus := <-collectorStatusCh:
			err = m.reportOtelStatusUpdate(ctx, otelStatus)
			if err != nil {
				reportErr(ctx, m.errCh, err)
>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
			}
		}
	}
}

// Errors returns channel that can send an error that affects the state of the running agent.
func (m *OTelManager) Errors() <-chan error {
	return m.errCh
}

<<<<<<< HEAD
// Update updates the configuration.
//
// When nil is passed for the cfg, then the collector is stopped.
func (m *OTelManager) Update(cfg *confmap.Conf) {
=======
// buildMergedConfig combines collector configuration with component-derived configuration.
func buildMergedConfig(
	cfgUpdate configUpdate,
	agentInfo info.Agent,
	monitoringConfigGetter translate.BeatMonitoringConfigGetter,
	logger *logp.Logger,
) (*confmap.Conf, error) {
	mergedOtelCfg := confmap.New()

	// Generate component otel config if there are components
	var componentOtelCfg *confmap.Conf
	if len(cfgUpdate.components) > 0 {
		model := &component.Model{Components: cfgUpdate.components}
		var err error
		componentOtelCfg, err = translate.GetOtelConfig(model, agentInfo, monitoringConfigGetter, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to generate otel config: %w", err)
		}
	}

	// If both configs are nil, return nil so the manager knows to stop the collector
	if componentOtelCfg == nil && cfgUpdate.collectorCfg == nil {
		return nil, nil
	}

	// Merge component config if it exists
	if componentOtelCfg != nil {
		err := mergedOtelCfg.Merge(componentOtelCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to merge component otel config: %w", err)
		}
	}

	// Merge with base collector config if it exists
	if cfgUpdate.collectorCfg != nil {
		err := mergedOtelCfg.Merge(cfgUpdate.collectorCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to merge collector otel config: %w", err)
		}
	}

	if err := addCollectorMetricsReader(mergedOtelCfg); err != nil {
		return nil, fmt.Errorf("failed to add random collector metrics port: %w", err)
	}

	if err := injectDiagnosticsExtension(mergedOtelCfg); err != nil {
		return nil, fmt.Errorf("failed to inject diagnostics: %w", err)
	}

	return mergedOtelCfg, nil
}

func injectDiagnosticsExtension(config *confmap.Conf) error {
	extensionCfg := map[string]any{
		"extensions": map[string]any{
			"elastic_diagnostics": map[string]any{
				"endpoint": paths.DiagnosticsExtensionSocket(),
			},
		},
	}
	if config.IsSet("service::extensions") {
		extensionList := config.Get("service::extensions").([]interface{})
		if slices.Contains(extensionList, "elastic_diagnostics") {
			// already configured, nothing to do
			return nil
		}
		extensionList = append(extensionList, "elastic_diagnostics")
		extensionCfg["service::extensions"] = extensionList
	}

	return config.Merge(confmap.NewFromStringMap(extensionCfg))
}

func (m *OTelManager) applyMergedConfig(ctx context.Context, collectorStatusCh chan *status.AggregateStatus, collectorRunErr chan error, forceFetchStatusCh chan struct{}) error {
	if m.proc != nil {
		m.proc.Stop(m.stopTimeout)
		m.proc = nil
		// We wait here for the collector to exit before possibly starting a new one. The execution indicates this
		// by sending an error over the appropriate channel. It will also send a nil status that we'll either process
		// after exiting from this function and going back to the main loop, or it will be overridden by the status
		// from the newly started collector.
		// This is the only blocking wait inside the main loop involving channels, so we need to be extra careful not to
		// deadlock.
		// TODO: Verify if we need to wait for the error at all. Stop() is already blocking.
		select {
		case <-collectorRunErr:
		case <-ctx.Done():
			// our caller ctx is Done
			return ctx.Err()
		}
	}

	if m.mergedCollectorCfg == nil {
		// no configuration then the collector should not be
		// running.
		// ensure that the coordinator knows that there is no error
		// as the collector is not running anymore
		return nil
	} else {
		// either a new configuration or the first configuration
		// that results in the collector being started
		proc, err := m.execution.startCollector(ctx, m.baseLogger, m.logger, m.mergedCollectorCfg, collectorRunErr, collectorStatusCh, forceFetchStatusCh)
		if err != nil {
			// failed to create the collector (this is different then
			// it's failing to run). we do not retry creation on failure
			// as it will always fail. A new configuration is required for
			// it not to fail (a new configuration will result in the retry)
			// since this is a new configuration we want to start the timer
			// from the initial delay
			recoveryDelay := m.recoveryTimer.ResetInitial()
			m.logger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
			return err
		} else {
			// all good at the moment (possible that it will fail)
			m.proc = proc
		}
	}
	return nil
}

// Update sends collector configuration and component updates to the manager's run loop.
func (m *OTelManager) Update(cfg *confmap.Conf, components []component.Component) {
	cfgUpdate := configUpdate{
		collectorCfg: cfg,
		components:   components,
	}

	// we care only about the latest config update
>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
	select {
	case m.cfgCh <- cfg:
	case <-m.doneChan:
		// shutting down, ignore the update
	}
}

// Watch returns a channel to watch for state information.
//
// This must be called and the channel must be read from, or it will block this manager.
func (m *OTelManager) Watch() <-chan *status.AggregateStatus {
	return m.statusCh
}

func (m *OTelManager) startCollector(cfg *confmap.Conf, errCh chan error) (context.CancelFunc, *agentprovider.Provider, error) {
	ctx, cancel := context.WithCancel(context.Background())
	ap := agentprovider.NewProvider(cfg)

	// NewForceExtensionConverterFactory is used to ensure that the agent_status extension is always enabled.
	// It is required for the Elastic Agent to extract the status out of the OTel collector.
	settings := otel.NewSettings(
		release.Version(), []string{ap.URI()},
		otel.WithConfigProviderFactory(ap.NewFactory()),
		otel.WithConfigConvertorFactory(NewForceExtensionConverterFactory(AgentStatusExtensionType.String())),
		otel.WithExtensionFactory(NewAgentStatusFactory(m)))
	settings.DisableGracefulShutdown = true // managed by this manager
	settings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return m.baseLogger.Core() // use the base logger also used for logs from the command runtime
	})}
	svc, err := otelcol.NewCollector(*settings)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	go func() {
		errCh <- svc.Run(ctx)
	}()
	return cancel, ap, nil
}

// reportErr reports an error to the service that is controlling this manager
//
// the manager can be blocked doing other work like sending this manager a new configuration
// so we do not want error reporting to be a blocking send over the channel
//
// the manager really only needs the most recent error, so if it misses an error it's not a big
// deal, what matters is that it has the current error for the state of this manager
func (m *OTelManager) reportErr(ctx context.Context, err error) {
	select {
	case <-m.errCh:
	default:
	}
	select {
<<<<<<< HEAD
	case m.errCh <- err:
=======
	case m.updateCh <- cfgUpdate:
	case <-m.doneChan:
		// Manager is shutting down, ignore the update
	}
}

// WatchCollector returns a read-only channel that provides collector status updates.
func (m *OTelManager) WatchCollector() <-chan *status.AggregateStatus {
	return m.collectorStatusCh
}

// WatchComponents returns a read-only channel that provides component state updates.
func (m *OTelManager) WatchComponents() <-chan []runtime.ComponentComponentState {
	return m.componentStateCh
}

func (m *OTelManager) MergedOtelConfig() *confmap.Conf {
	m.mx.RLock()
	defer m.mx.RUnlock()
	return m.mergedCollectorCfg
}

// handleOtelStatusUpdate processes status updates from the underlying OTelManager.
// This method extracts component states from the aggregate status, updates internal state tracking,
// and prepares component state updates for distribution to watchers.
// Returns component state updates and any error encountered during processing.
func (m *OTelManager) handleOtelStatusUpdate(otelStatus *status.AggregateStatus) ([]runtime.ComponentComponentState, error) {
	// Remove agent managed extensions from the status report
	if otelStatus != nil {
		if extensionsMap, exists := otelStatus.ComponentStatusMap["extensions"]; exists {
			for extensionKey := range extensionsMap.ComponentStatusMap {
				switch {
				case strings.HasPrefix(extensionKey, "extension:beatsauth"):
					delete(extensionsMap.ComponentStatusMap, extensionKey)
				case strings.HasPrefix(extensionKey, "extension:elastic_diagnostics"):
					delete(extensionsMap.ComponentStatusMap, extensionKey)
				}
			}

			if len(extensionsMap.ComponentStatusMap) == 0 {
				delete(otelStatus.ComponentStatusMap, "extensions")
			}
		}
	}

	otelStatus, err := translate.MaybeMuteExporterStatus(otelStatus, m.components)
	if err != nil {
		return nil, fmt.Errorf("failed to mute exporter states from otel status: %w", err)
	}

	// Extract component states from otel status
	componentStates, err := translate.GetAllComponentStates(otelStatus, m.components)
	if err != nil {
		return nil, fmt.Errorf("failed to extract component states: %w", err)
	}

	// Drop component state information from otel status
	finalStatus, err := translate.DropComponentStateFromOtelStatus(otelStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to drop component state from otel status: %w", err)
	}

	// Update the current collector status to the cleaned status (after dropping component states)
	m.currentCollectorStatus = finalStatus

	// Handle component state updates
	return m.processComponentStates(componentStates), nil
}

// reportOtelStatusUpdate processes status updates from the underlying otel collector and reports separate collector
// and component state updates to the external watch channels.
func (m *OTelManager) reportOtelStatusUpdate(ctx context.Context, otelStatus *status.AggregateStatus) error {
	componentUpdates, err := m.handleOtelStatusUpdate(otelStatus)
	if err != nil {
		return err
	}
	reportCollectorStatus(ctx, m.collectorStatusCh, m.currentCollectorStatus)
	m.reportComponentStateUpdates(ctx, componentUpdates)
	return nil
}

// processComponentStates updates the internal component state tracking and handles cleanup
// of components that are no longer in the configuration. This method ensures that removed
// components are properly marked as STOPPED even if no explicit stop event was received.
func (m *OTelManager) processComponentStates(componentStates []runtime.ComponentComponentState) []runtime.ComponentComponentState {
	// Drop component states which don't exist in the configuration anymore
	// we need to do this because we aren't guaranteed to receive a STOPPED state when the component is removed
	componentIds := make(map[string]bool)
	for _, componentState := range componentStates {
		componentIds[componentState.Component.ID] = true
	}
	for id := range m.currentComponentStates {
		if _, ok := componentIds[id]; !ok {
			// this component is not in the configuration anymore, emit a fake STOPPED state
			componentStates = append(componentStates, runtime.ComponentComponentState{
				Component: component.Component{
					ID: id,
				},
				State: runtime.ComponentState{
					State: client.UnitStateStopped,
				},
			})
		}
	}

	// update the current state
	m.currentComponentStates = make(map[string]runtime.ComponentComponentState)
	for _, componentState := range componentStates {
		if componentState.State.State == client.UnitStateStopped {
			delete(m.currentComponentStates, componentState.Component.ID)
		} else {
			m.currentComponentStates[componentState.Component.ID] = componentState
		}
	}

	return componentStates
}

// maybeUpdateMergedConfig updates the merged config if it's different from the current value. It checks this by
// calculating a hash and comparing. It returns a value indicating if the configuration was updated.
// If an error is encountered when calculating the hash, this will always be true.
func (m *OTelManager) maybeUpdateMergedConfig(mergedCfg *confmap.Conf) (updated bool, err error) {
	// if we get an error here, we just proceed with the update, worst that can happen is that we reload unnecessarily
	mergedCfgHash, err := calculateConfmapHash(mergedCfg)
	previousConfigHash := m.mergedCollectorCfgHash

	m.mergedCollectorCfg = mergedCfg
	m.mergedCollectorCfgHash = mergedCfgHash
	return !bytes.Equal(mergedCfgHash, previousConfigHash) || err != nil, err
}

// reportComponentStateUpdates sends component state updates to the component watch channel. It is synchronous and
// blocking - the update must be received before this function returns. We are not allowed to drop older updates
// in favor of newer ones here, as the coordinator expected incremental updates.
func (m *OTelManager) reportComponentStateUpdates(ctx context.Context, componentUpdates []runtime.ComponentComponentState) {
	select {
	case m.componentStateCh <- componentUpdates:
>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
	case <-ctx.Done():
	}
}
