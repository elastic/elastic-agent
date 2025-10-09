// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
<<<<<<< HEAD
=======
	"fmt"
	"hash/fnv"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"

	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
>>>>>>> d8f1daeae (fix: do not report agent managed otel extensions statuses (#10412))

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
	logger *logger.Logger
	errCh  chan error

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
func NewOTelManager(logger *logger.Logger) *OTelManager {
	return &OTelManager{
		logger:   logger,
		errCh:    make(chan error, 1), // holds at most one error
		cfgCh:    make(chan *confmap.Conf),
		statusCh: make(chan *status.AggregateStatus),
		doneChan: make(chan struct{}),
	}
}

// Run runs the lifecycle of the manager.
func (m *OTelManager) Run(ctx context.Context) error {
	var err error
	var cancel context.CancelFunc
	var provider *agentprovider.Provider

	// signal that the run loop is ended to unblock any incoming update calls
	defer close(m.doneChan)

	runErrCh := make(chan error)
	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
				<-runErrCh // wait for collector to be stopped
			}
			return ctx.Err()
		case err = <-runErrCh:
			if err == nil {
				// err is nil but there is a configuration
				//
				// in this rare case the collector stopped running but a configuration was
				// provided and the collector stopped with a clean exit
				cancel()
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
			}
		}
	}
}

// Errors returns channel that can send an error that affects the state of the running agent.
func (m *OTelManager) Errors() <-chan error {
	return m.errCh
}

// Update updates the configuration.
//
// When nil is passed for the cfg, then the collector is stopped.
func (m *OTelManager) Update(cfg *confmap.Conf) {
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
		return m.logger.Core() // use same zap as agent
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
<<<<<<< HEAD
	case <-m.errCh:
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

// reportComponentStateUpdates sends component state updates to the component watch channel. It first drains
// the channel to ensure that only the most recent status is kept, as intermediate statuses can be safely discarded.
// This ensures the receiver always observes the latest reported status.
func (m *OTelManager) reportComponentStateUpdates(ctx context.Context, componentUpdates []runtime.ComponentComponentState) {
	select {
	case <-ctx.Done():
		// context is already done
		return
	case <-m.componentStateCh:
	// drain the channel first
>>>>>>> d8f1daeae (fix: do not report agent managed otel extensions statuses (#10412))
	default:
	}
	select {
	case m.errCh <- err:
	case <-ctx.Done():
	}
}
