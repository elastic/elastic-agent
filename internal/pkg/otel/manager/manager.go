// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type ExecutionMode string

const (
	SubprocessExecutionMode ExecutionMode = "subprocess"
	EmbeddedExecutionMode   ExecutionMode = "embedded"
)

type collectorRecoveryTimer interface {
	// IsStopped returns true if the timer is stopped
	IsStopped() bool
	// Stop stops the timer
	Stop()
	// ResetInitial resets the timer to the initial interval
	ResetInitial() time.Duration
	// ResetNext resets the timer to the next interval
	ResetNext() time.Duration
	// C returns the timer channel
	C() <-chan time.Time
}

type configUpdate struct {
	collectorCfg *confmap.Conf
	components   []component.Component
}

// OTelManager is a manager that manages the lifecycle of the OTel collector inside of the Elastic Agent.
type OTelManager struct {
	// baseLogger is the base logger for the otel collector, and doesn't include any agent-specific fields.
	baseLogger *logger.Logger
	logger     *logger.Logger
	errCh      chan error

	// Agent info and monitoring config getter for otel config generation
	agentInfo                  info.Agent
	beatMonitoringConfigGetter translate.BeatMonitoringConfigGetter

	collectorCfg *confmap.Conf
	components   []component.Component

	// The current configuration that the OTel collector is using. In the case that
	// the mergedCollectorCfg is nil then the collector is not running.
	mergedCollectorCfg *confmap.Conf

	currentCollectorStatus *status.AggregateStatus
	currentComponentStates map[string]runtime.ComponentComponentState

	// Update channels for forwarding updates to the run loop
	updateCh chan configUpdate

	// Status channels for reading status from the run loop
	collectorStatusCh chan *status.AggregateStatus
	componentStateCh  chan []runtime.ComponentComponentState

	// This mutex is used to protect access to attributes read outside the run loop. This happens when reading the
	// merged config and generating diagnostics.
	mx sync.RWMutex

	// doneChan is closed when Run is stopped to signal that any
	// pending update calls should be ignored.
	doneChan chan struct{}

	// recoveryTimer is used to restart the collector when it has errored.
	recoveryTimer collectorRecoveryTimer

	// recoveryRetries is the number of times the collector has been
	// restarted through the recovery timer.
	recoveryRetries atomic.Uint32

	// execution is used to invoke the collector into different execution modes
	execution collectorExecution

	proc collectorHandle

	// collectorRunErr is used to signal that the collector has exited.
	collectorRunErr chan error

	// stopTimeout is the timeout to wait for the collector to stop.
	stopTimeout time.Duration
}

// NewOTelManager returns a OTelManager.
func NewOTelManager(
	logger *logger.Logger,
	logLevel logp.Level,
	baseLogger *logger.Logger,
	mode ExecutionMode,
	agentInfo info.Agent,
	beatMonitoringConfigGetter translate.BeatMonitoringConfigGetter,
	stopTimeout time.Duration,
) (*OTelManager, error) {
	var exec collectorExecution
	var recoveryTimer collectorRecoveryTimer
	switch mode {
	case SubprocessExecutionMode:
		// NOTE: if we stop embedding the collector binary in elastic-agent, we need to
		// change this
		executable, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get the path to the collector executable: %w", err)
		}
		recoveryTimer = newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute)
		exec, err = newSubprocessExecution(logLevel, executable)
		if err != nil {
			return nil, fmt.Errorf("failed to create subprocess execution: %w", err)
		}
	case EmbeddedExecutionMode:
		recoveryTimer = newRestarterNoop()
		exec = newExecutionEmbedded()
	default:
		return nil, fmt.Errorf("unknown otel collector execution mode: %q", mode)
	}

	logger.Debugf("Using collector execution mode: %s", mode)

	return &OTelManager{
		logger:                     logger,
		baseLogger:                 baseLogger,
		agentInfo:                  agentInfo,
		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
		errCh:                      make(chan error, 1), // holds at most one error
		collectorStatusCh:          make(chan *status.AggregateStatus, 1),
		componentStateCh:           make(chan []runtime.ComponentComponentState, 1),
		updateCh:                   make(chan configUpdate, 1),
		doneChan:                   make(chan struct{}),
		execution:                  exec,
		recoveryTimer:              recoveryTimer,
		collectorRunErr:            make(chan error),
		stopTimeout:                stopTimeout,
	}, nil
}

// Run runs the lifecycle of the manager.
func (m *OTelManager) Run(ctx context.Context) error {
	var err error
	m.proc = nil

	// collectorStatusCh is used internally by the otel collector to send status updates to the manager
	// this channel is buffered because it's possible for the collector to send a status update while the manager is
	// waiting for the collector to exit
	collectorStatusCh := make(chan *status.AggregateStatus, 1)
	for {
		select {
		case <-ctx.Done():
			// signal that the run loop is ended to unblock any incoming update calls
			close(m.doneChan)

			m.recoveryTimer.Stop()
			// our caller context is cancelled so stop the collector and return
			// has exited.
			if m.proc != nil {
				m.proc.Stop(m.stopTimeout)
			}
			return ctx.Err()
		case <-m.recoveryTimer.C():
			m.recoveryTimer.Stop()

			if m.mergedCollectorCfg == nil || m.proc != nil || ctx.Err() != nil {
				// no configuration, or the collector is already running, or the context
				// is cancelled.
				continue
			}

			newRetries := m.recoveryRetries.Add(1)
			m.logger.Infof("collector recovery restarting, total retries: %d", newRetries)
			m.proc, err = m.execution.startCollector(ctx, m.baseLogger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh)
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
			if err == nil {
				// err is nil means that the collector has exited cleanly without an error
				if m.proc != nil {
					m.proc.Stop(m.stopTimeout)
					m.proc = nil
					updateErr := m.reportOtelStatusUpdate(ctx, nil)
					if updateErr != nil {
						reportErr(ctx, m.errCh, updateErr)
					}
				}

				if m.mergedCollectorCfg == nil {
					// no configuration then the collector should not be
					// running.
					// ensure that the coordinator knows that there is no error
					// as the collector is not running anymore
					reportErr(ctx, m.errCh, nil)
					continue
				}

				m.logger.Warnf("collector exited without an error but a configuration was provided")

				// in this rare case the collector stopped running but a configuration was
				// provided and the collector stopped with a clean exit
				m.proc, err = m.execution.startCollector(ctx, m.baseLogger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh)
				if err != nil {
					// failed to create the collector (this is different then
					// it's failing to run). we do not retry creation on failure
					// as it will always fail. A new configuration is required for
					// it not to fail (a new configuration will result in the retry)
					reportErr(ctx, m.errCh, err)
					// reset the restart timer to the next backoff
					recoveryDelay := m.recoveryTimer.ResetNext()
					m.logger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
				} else {
					// all good at the moment (possible that it will fail)
					reportErr(ctx, m.errCh, nil)
				}
			} else {
				// error occurred while running the collector, this occurs in the
				// case that the configuration is invalid once the collector is started
				// or the context for running the collector is cancelled.
				//
				// in the case that the configuration is invalid there is no reason to
				// try again as it will keep failing so we do not trigger a restart
				if m.proc != nil {
					m.proc.Stop(m.stopTimeout)
					m.proc = nil
					// don't wait here for <-collectorRunErr, already occurred
					// clear status, no longer running
					updateErr := m.reportOtelStatusUpdate(ctx, nil)
					if updateErr != nil {
						err = errors.Join(err, updateErr)
					}
				}
				// pass the error to the errCh so the coordinator, unless it's a cancel error
				if !errors.Is(err, context.Canceled) {
					reportErr(ctx, m.errCh, err)
					// reset the restart timer to the next backoff
					recoveryDelay := m.recoveryTimer.ResetNext()
					m.logger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
				}
			}

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
			m.mergedCollectorCfg = mergedCfg
			m.collectorCfg = cfgUpdate.collectorCfg
			m.components = cfgUpdate.components
			m.mx.Unlock()

			err = m.applyMergedConfig(ctx, collectorStatusCh, m.collectorRunErr)
			// report the error unconditionally to indicate that the config was applied
			reportErr(ctx, m.errCh, err)

		case otelStatus := <-collectorStatusCh:
			err = m.reportOtelStatusUpdate(ctx, otelStatus)
			if err != nil {
				reportErr(ctx, m.errCh, err)
			}
		}
	}
}

// Errors returns channel that can send an error that affects the state of the running agent.
func (m *OTelManager) Errors() <-chan error {
	return m.errCh
}

// buildMergedConfig combines collector configuration with component-derived configuration.
func buildMergedConfig(cfgUpdate configUpdate, agentInfo info.Agent, monitoringConfigGetter translate.BeatMonitoringConfigGetter, logger *logp.Logger) (*confmap.Conf, error) {
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

	return mergedOtelCfg, nil
}

func (m *OTelManager) applyMergedConfig(ctx context.Context, collectorStatusCh chan *status.AggregateStatus, collectorRunErr chan error) error {
	if m.proc != nil {
		m.proc.Stop(m.stopTimeout)
		m.proc = nil
		select {
		case <-collectorRunErr:
		case <-ctx.Done():
			// our caller ctx is Done
			return ctx.Err()
		}
		// drain the internal status update channel
		// this status handling is normally done in the main loop, but in this case we want to ensure that we emit a
		// nil status after the collector has stopped
		select {
		case statusCh := <-collectorStatusCh:
			updateErr := m.reportOtelStatusUpdate(ctx, statusCh)
			if updateErr != nil {
				m.logger.Error("failed to update otel status", zap.Error(updateErr))
			}
		case <-ctx.Done():
			// our caller ctx is Done
			return ctx.Err()
		default:
		}
		err := m.reportOtelStatusUpdate(ctx, nil)
		if err != nil {
			return err
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
		proc, err := m.execution.startCollector(ctx, m.baseLogger, m.mergedCollectorCfg, collectorRunErr, collectorStatusCh)
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
	select {
	case <-m.updateCh:
	case <-m.doneChan:
		return
	default:
	}

	select {
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
	default:
	}
	select {
	case m.componentStateCh <- componentUpdates:
	case <-ctx.Done():
		// Manager is shutting down, ignore the update
		return
	}
}
