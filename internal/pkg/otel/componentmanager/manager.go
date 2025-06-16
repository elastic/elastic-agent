// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package componentmanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// OTelManager provides an interface to run and update the runtime.
type OTelManager interface {
	// Run runs the manager.
	Run(context.Context) error

	// Errors returns the channel to listen to errors on.
	//
	// A manager should send a nil error to clear its previous error when it should no longer report as an error.
	Errors() <-chan error

	// Update updates the current configuration for OTel.
	Update(cfg *confmap.Conf)

	// Watch returns the chanel to watch for configuration changes.
	Watch() <-chan *status.AggregateStatus
}

// OtelComponentManager provides an interface to run components and plain otel configurations in an otel collector.
// Both the components and the otel configurations run in the same collector instance, but can be updated and
// subscribed to separately.
type OtelComponentManager struct {
	logger      *logger.Logger
	otelManager OTelManager

	// Agent info and monitoring config getter for otel config generation
	agentInfo                  info.Agent
	beatMonitoringConfigGetter translate.BeatMonitoringConfigGetter

	collectorCfg *confmap.Conf
	components   []component.Component

	collectorConfigMutex sync.RWMutex
	mergedCollectorCfg   *confmap.Conf

	currentCollectorStatus *status.AggregateStatus
	currentComponentStates map[string]runtime.ComponentComponentState

	// Update channels for forwarding updates to the run loop
	collectorUpdateChan chan *confmap.Conf
	componentUpdateChan chan component.Model
	errCh               chan error

	// Watch channels for external consumers
	collectorWatchChan chan *status.AggregateStatus
	componentWatchChan chan runtime.ComponentComponentState

	// doneChan is closed when manager is shutting down
	doneChan chan struct{}
}

// NewOtelComponentManager creates a new OtelComponentManager instance with the provided dependencies.
// The manager coordinates between component configurations and OpenTelemetry collector configurations,
// allowing both to run in the same collector instance while being updated and monitored separately.
//
// Returns a configured OtelComponentManager ready to be started with Run().
func NewOtelComponentManager(logger *logger.Logger, otelManager OTelManager, agentInfo info.Agent, beatMonitoringConfigGetter translate.BeatMonitoringConfigGetter) *OtelComponentManager {
	return &OtelComponentManager{
		logger:                     logger,
		otelManager:                otelManager,
		agentInfo:                  agentInfo,
		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
		currentComponentStates:     make(map[string]runtime.ComponentComponentState),
		collectorWatchChan:         make(chan *status.AggregateStatus),
		componentWatchChan:         make(chan runtime.ComponentComponentState),
		collectorUpdateChan:        make(chan *confmap.Conf),
		componentUpdateChan:        make(chan component.Model),
		errCh:                      make(chan error, 1),
		doneChan:                   make(chan struct{}),
	}
}

// Run starts the OtelComponentManager's main event loop and manages the lifecycle of the OpenTelemetry collector.
// This method blocks until the context is cancelled and handles all configuration updates, status monitoring,
// and error reporting in a thread-safe manner.
//
// The run loop processes the following events:
//   - Collector configuration updates via UpdateCollector()
//   - Component model updates via UpdateComponents()
//   - Status updates from the underlying OpenTelemetry manager
//   - Error reporting and propagation
//
// Returns the context error.
func (m *OtelComponentManager) Run(ctx context.Context) error {
	// Initialize any required state
	m.logger.Debug("Starting OtelComponentManager run loop")

	// Start the otel manager
	go func() {
		if err := m.otelManager.Run(ctx); err != nil && ctx.Err() == nil {
			m.reportError(ctx, fmt.Errorf("otel manager error: %w", err))
		}
	}()

	// Main run loop - read from internal channels and handle updates
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			m.logger.Debug("OtelComponentManager run loop context cancelled")
			break

		case collectorCfg := <-m.collectorUpdateChan:
			m.logger.Debug("Received collector configuration update")
			if err := m.handleCollectorUpdate(collectorCfg); err != nil {
				m.reportError(ctx, err)
			}

		case componentModel := <-m.componentUpdateChan:
			m.logger.Debug("Received component model update")
			if err := m.handleComponentUpdate(componentModel); err != nil {
				m.reportError(ctx, err)
			}

		case err := <-m.errCh:
			m.logger.Debug("Received error from otel manager")
			m.reportError(ctx, err)

		case otelStatus := <-m.otelManager.Watch():
			m.logger.Debug("Received status update from otel manager")
			componentUpdates, err := m.handleOtelStatusUpdate(otelStatus)
			if err != nil {
				m.reportError(ctx, err)
			}
			m.sendCollectorStatusUpdate(ctx)
			m.sendComponentStateUpdates(ctx, componentUpdates)
		}
	}

	// Signal shutdown
	close(m.doneChan)
	return ctx.Err()
}

// handleCollectorUpdate processes collector configuration updates received through the collectorUpdateChan.
// This method updates the internal collector configuration and triggers a rebuild of the merged
// configuration that combines collector and component configurations.
func (m *OtelComponentManager) handleCollectorUpdate(cfg *confmap.Conf) error {
	m.collectorCfg = cfg
	return m.updateMergedConfig()
}

// handleComponentUpdate processes component model updates received through the componentUpdateChan.
// This method updates the internal component list and triggers a rebuild of the merged
// configuration that combines collector and component configurations.
func (m *OtelComponentManager) handleComponentUpdate(model component.Model) error {
	m.components = model.Components
	return m.updateMergedConfig()
}

// buildMergedConfig combines collector configuration with component-derived configuration.
func (m *OtelComponentManager) buildMergedConfig() (*confmap.Conf, error) {
	mergedOtelCfg := confmap.New()

	// Generate component otel config if there are components
	var componentOtelCfg *confmap.Conf
	if len(m.components) > 0 {
		model := &component.Model{Components: m.components}
		var err error
		m.logger.With("components", m.components).Debug("Updating otel manager model")
		componentOtelCfg, err = translate.GetOtelConfig(model, m.agentInfo, m.beatMonitoringConfigGetter)
		if err != nil {
			return nil, fmt.Errorf("failed to generate otel config: %w", err)
		}
		componentIDs := make([]string, 0, len(m.components))
		for _, comp := range m.components {
			componentIDs = append(componentIDs, comp.ID)
		}
		m.logger.With("component_ids", componentIDs).Warn("The Otel runtime manager is HIGHLY EXPERIMENTAL and only intended for testing. Use at your own risk.")
	}

	// Merge component config if it exists
	if componentOtelCfg != nil {
		err := mergedOtelCfg.Merge(componentOtelCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to merge component otel config: %w", err)
		}
	}

	// Merge with base collector config if it exists
	if m.collectorCfg != nil {
		err := mergedOtelCfg.Merge(m.collectorCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to merge collector otel config: %w", err)
		}
	}

	// If the config is empty, return nil so the manager knows to stop the collector
	if len(mergedOtelCfg.AllKeys()) == 0 {
		return nil, nil
	}

	return mergedOtelCfg, nil
}

// updateMergedConfig builds the merged configuration for the otel manager by merging the base collector configuration
// with the component configuration, and updates the otel manager with the merged configuration.
func (m *OtelComponentManager) updateMergedConfig() error {
	mergedCfg, err := m.buildMergedConfig()
	if err != nil {
		return err
	}

	m.otelManager.Update(mergedCfg)

	m.collectorConfigMutex.Lock()
	defer m.collectorConfigMutex.Unlock()
	m.mergedCollectorCfg = mergedCfg
	return nil
}

// reportErr reports an error to the service that is controlling this manager
//
// The manager can be blocked doing other work like sending this manager a new configuration
// so we do not want error reporting to be a blocking send over the channel
//
// the manager really only needs the most recent error, so if it misses an error it's not a big
// deal, what matters is that it has the current error for the state of this manager
func (m *OtelComponentManager) reportError(ctx context.Context, err error) {
	select {
	case <-m.errCh:
	default:
	}
	select {
	case m.errCh <- err:
	case <-ctx.Done():
		// Manager is shutting down, ignore the update
	}
}

// Errors returns a read-only channel that provides access to errors reported by the manager.
func (m *OtelComponentManager) Errors() <-chan error {
	return m.errCh
}

// UpdateCollector sends a collector configuration update to the manager's run loop.
func (m *OtelComponentManager) UpdateCollector(cfg *confmap.Conf) {
	select {
	case m.collectorUpdateChan <- cfg:
	case <-m.doneChan:
		// Manager is shutting down, ignore the update
	}
}

// UpdateComponents sends a component model update to the manager's run loop.
func (m *OtelComponentManager) UpdateComponents(model component.Model) {
	select {
	case m.componentUpdateChan <- model:
	case <-m.doneChan:
		// Manager is shutting down, ignore the update
	}
}

// WatchCollector returns a read-only channel that provides collector status updates.
func (m *OtelComponentManager) WatchCollector() <-chan *status.AggregateStatus {
	return m.collectorWatchChan
}

// WatchComponents returns a read-only channel that provides component state updates.
func (m *OtelComponentManager) WatchComponents() <-chan runtime.ComponentComponentState {
	return m.componentWatchChan
}

func (m *OtelComponentManager) MergedOtelConfig() *confmap.Conf {
	m.collectorConfigMutex.RLock()
	defer m.collectorConfigMutex.RUnlock()
	return m.mergedCollectorCfg
}

// handleOtelStatusUpdate processes status updates from the underlying OpenTelemetry manager.
// This method extracts component states from the aggregate status, updates internal state tracking,
// and prepares component state updates for distribution to watchers.
// Returns component state updates and any error encountered during processing.
func (m *OtelComponentManager) handleOtelStatusUpdate(otelStatus *status.AggregateStatus) ([]runtime.ComponentComponentState, error) {
	// Extract component states from otel status, similar to coordinator's watchRuntimeComponents
	componentStates, err := translate.GetAllComponentStates(otelStatus, m.components)
	if err != nil {
		return nil, fmt.Errorf("failed to extract component states: %w", err)
	}

	// Drop component state information from otel status (modifies the status in place)
	err = translate.DropComponentStateFromOtelStatus(otelStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to drop component state from otel status: %w", err)
	}

	// Update the current collector status to the cleaned status (after dropping component states)
	m.currentCollectorStatus = otelStatus

	// Handle component state updates
	if componentStates != nil {
		return m.processComponentStates(componentStates), nil
	}

	return nil, nil
}

// processComponentStates updates the internal component state tracking and handles cleanup
// of components that are no longer in the configuration. This method ensures that removed
// components are properly marked as STOPPED even if no explicit stop event was received.
func (m *OtelComponentManager) processComponentStates(componentStates []runtime.ComponentComponentState) []runtime.ComponentComponentState {
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

// sendCollectorStatusUpdate sends the current collector status to the collector watch channel.
func (m *OtelComponentManager) sendCollectorStatusUpdate(ctx context.Context) {
	select {
	case m.collectorWatchChan <- m.currentCollectorStatus:
	case <-ctx.Done():
		// Manager is shutting down, ignore the update
	}
}

// sendComponentStateUpdates sends component state updates to the component watch channel.
func (m *OtelComponentManager) sendComponentStateUpdates(ctx context.Context, componentUpdates []runtime.ComponentComponentState) {
	for _, componentState := range componentUpdates {
		select {
		case m.componentWatchChan <- componentState:
		case <-ctx.Done():
			// Manager is shutting down, ignore the update
			return
		}
	}
}
