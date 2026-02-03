// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"

	otelcomponent "go.opentelemetry.io/collector/component"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	elasticmonitoringreceiver "github.com/elastic/elastic-agent/internal/pkg/otel/receivers/elasticmonitoring"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	// CollectorStopTimeout is the duration to wait for the collector to stop. Note: this needs to be shorter
	// than 5 * time.Second (coordinator.managerShutdownTimeout) otherwise we might end up with a defunct process.
	CollectorStopTimeout = 3 * time.Second
	// OtelCollectorMetricsPortEnvVarName is the name of the environment variable used to pass the collector metrics
	// port to the managed EDOT collector.
	OtelCollectorMetricsPortEnvVarName = "EDOT_COLLECTOR_METRICS_PORT"
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
	collectorCfg  *confmap.Conf
	monitoringCfg *monitoringCfg.MonitoringConfig
	components    []component.Component
	agentLogLevel logp.Level
}

// OTelManager is a manager that manages the lifecycle of the OTel collector inside of the Elastic Agent.
type OTelManager struct {
	// collectorLogger is the base logger for the otel collector, and doesn't include any agent-specific fields.
	collectorLogger *logger.Logger
	managerLogger   *logger.Logger

	// errCh should only be used to send critical errors that will mark the entire elastic-agent as failed
	// if it's an issue with starting or running the collector those should not be critical errors, instead
	// they should be reported as failed components to the elastic-agent
	errCh chan error

	// Agent info and monitoring config getter for otel config generation
	agentInfo                  info.Agent
	beatMonitoringConfigGetter translate.BeatMonitoringConfigGetter

	healthCheckExtID string
	collectorCfg     *confmap.Conf
	components       []component.Component

	// The current configuration that the OTel collector is using. In the case that
	// the mergedCollectorCfg is nil then the collector is not running.
	mergedCollectorCfg     *confmap.Conf
	mergedCollectorCfgHash []byte

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

	// log level of the collector
	collectorLogLevel logp.Level
}

// NewOTelManager returns a OTelManager.
func NewOTelManager(
	logger *logger.Logger,
	collectorLogLevel logp.Level,
	collectorLogger *logger.Logger,
	agentInfo info.Agent,
	agentCollectorConfig *configuration.CollectorConfig,
	beatMonitoringConfigGetter translate.BeatMonitoringConfigGetter,
	stopTimeout time.Duration,
) (*OTelManager, error) {
	var exec collectorExecution
	var recoveryTimer collectorRecoveryTimer
	var err error

	hcUUID, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("cannot generate UUID: %w", err)
	}
	hcUUIDStr := hcUUID.String()

	// determine the otel collector ports
	collectorMetricsPort, collectorHealthCheckPort := 0, 0
	if agentCollectorConfig != nil {
		if agentCollectorConfig.HealthCheckConfig.Endpoint != "" {
			collectorHealthCheckPort, err = agentCollectorConfig.HealthCheckConfig.Port()
			if err != nil {
				return nil, fmt.Errorf("invalid collector health check port: %w", err)
			}
		}
		if agentCollectorConfig.TelemetryConfig.Endpoint != "" {
			collectorMetricsPort, err = agentCollectorConfig.TelemetryConfig.Port()
			if err != nil {
				return nil, fmt.Errorf("invalid collector metrics port: %w", err)
			}
		}
	}

	executable := filepath.Join(paths.Components(), collectorBinaryName)
	recoveryTimer = newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute)
	exec, err = newSubprocessExecution(executable, hcUUIDStr, collectorMetricsPort, collectorHealthCheckPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create subprocess execution: %w", err)
	}

	return &OTelManager{
		managerLogger:              logger,
		collectorLogger:            collectorLogger,
		agentInfo:                  agentInfo,
		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
		healthCheckExtID:           fmt.Sprintf("extension:healthcheckv2/%s", hcUUIDStr),
		errCh:                      make(chan error, 1), // holds at most one error
		collectorStatusCh:          make(chan *status.AggregateStatus, 1),
		// componentStateCh uses a buffer channel to ensure that no state transitions are missed and to prevent
		// any possible case of deadlock, 5 is used just to give a small buffer.
		componentStateCh:  make(chan []runtime.ComponentComponentState, 5),
		updateCh:          make(chan configUpdate, 1),
		doneChan:          make(chan struct{}),
		execution:         exec,
		recoveryTimer:     recoveryTimer,
		collectorRunErr:   make(chan error),
		stopTimeout:       stopTimeout,
		collectorLogLevel: collectorLogLevel,
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
	forceFetchStatusCh := make(chan struct{}, 1)
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

			// at this point no critical errors are occurring
			// any issues starting the collector are reporting in the status
			reportErr(ctx, m.errCh, nil)

			newRetries := m.recoveryRetries.Add(1)
			m.managerLogger.Infof("collector recovery restarting, total retries: %d", newRetries)
			m.proc, err = m.execution.startCollector(ctx, m.collectorLogLevel, m.collectorLogger,
				m.managerLogger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh, forceFetchStatusCh)
			if err != nil {
				// report a startup error (this gets reported as status)
				m.reportStartupErr(ctx, err)
				// reset the restart timer to the next backoff
				recoveryDelay := m.recoveryTimer.ResetNext()
				m.managerLogger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
			}
		case err = <-m.collectorRunErr:
			m.recoveryTimer.Stop()
			if err == nil {
				// err is nil means that the collector has exited cleanly without an error
				if m.proc != nil {
					m.proc.Stop(m.stopTimeout)
					m.proc = nil
				}

				// no critical error from this point forward
				reportErr(ctx, m.errCh, nil)

				if m.mergedCollectorCfg == nil {
					// no configuration then the collector should not be
					// running.
					continue
				}

				m.managerLogger.Warnf("collector exited without an error but a configuration was provided")

				// in this rare case the collector stopped running but a configuration was
				// provided and the collector stopped with a clean exit
				m.proc, err = m.execution.startCollector(ctx, m.collectorLogLevel, m.collectorLogger,
					m.managerLogger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh, forceFetchStatusCh)
				if err != nil {
					// report a startup error (this gets reported as status)
					m.reportStartupErr(ctx, err)
					// reset the restart timer to the next backoff
					recoveryDelay := m.recoveryTimer.ResetNext()
					m.managerLogger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
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
				}
				// pass the error to the errCh so the coordinator, unless it's a cancel error
				if !errors.Is(err, context.Canceled) {
					// report a startup error (this gets reported as status)
					m.reportStartupErr(ctx, err)
					// reset the restart timer to the next backoff
					recoveryDelay := m.recoveryTimer.ResetNext()
					m.managerLogger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
				}
			}

		case cfgUpdate := <-m.updateCh:
			// we received a new configuration, thus stop the recovery timer
			// and reset the retry count
			m.recoveryTimer.Stop()
			m.recoveryRetries.Store(0)
			mergedCfg, err := buildMergedConfig(cfgUpdate, m.agentInfo, m.beatMonitoringConfigGetter, m.managerLogger)
			if err != nil {
				// critical error, merging the configuration should always work
				reportErr(ctx, m.errCh, err)
				continue
			}

			// this is the only place where we mutate the internal config attributes, take a write lock for the duration
			m.mx.Lock()
			previousConfigHash := m.mergedCollectorCfgHash
			configChanged, configUpdateErr := m.maybeUpdateMergedConfig(mergedCfg)
			m.collectorCfg = cfgUpdate.collectorCfg
			m.components = cfgUpdate.components
			lvl, err := newLogLevelAfterConfigUpdate(cfgUpdate, mergedCfg)
			if err != nil {
				m.managerLogger.Warnf("failed to determine new log level: %s", err)
			} else {
				m.collectorLogLevel = lvl
			}
			m.mx.Unlock()

			if configUpdateErr != nil {
				m.managerLogger.Warn("failed to calculate hash of merged config, proceeding with update", zap.Error(configUpdateErr))
			}

			if configChanged {
				m.managerLogger.Debugf(
					"new config hash (%d) is different than the old config hash (%d), applying update",
					m.mergedCollectorCfgHash, previousConfigHash)
				applyErr := m.applyMergedConfig(ctx, collectorStatusCh, m.collectorRunErr, forceFetchStatusCh)
				// only report the error if we actually apply the update
				// otherwise, we could override an actual error with a nil in the channel when the collector
				// state doesn't actually change
				reportErr(ctx, m.errCh, applyErr)
			} else {
				m.managerLogger.Debugf(
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
				// critical error and not handling the status update correctly
				// can't properly report status if this fails, so we report it as critical
				reportErr(ctx, m.errCh, err)
			} else {
				// status update was able to be reporting clear any critical error
				reportErr(ctx, m.errCh, nil)
			}
		}
	}
}

// Errors returns channel that can send an error that affects the state of the running agent.
func (m *OTelManager) Errors() <-chan error {
	return m.errCh
}

// newLogLevelAfterConfigUpdate returns the manager log level after a configuration update, which can
// be the log level set directly in the collector configuration or if that is not set, the log level
// of the coordinator (the log level set in the Elastic Agent configuration).
func newLogLevelAfterConfigUpdate(cfgUpdate configUpdate, mergedCfg *confmap.Conf) (logp.Level, error) {
	// Prefer the log level defined in the collector configuration to prioritize a user defined collector log level.
	if mergedCfg != nil && mergedCfg.IsSet("service::telemetry::logs::level") {
		if otelLevel, ok := mergedCfg.Get("service::telemetry::logs::level").(string); ok {
			return translate.OTelLevelToLogp(otelLevel)
		} else {
			return logp.DebugLevel, errors.New("service::telemetry::logs::level found but was not of type string")
		}
	} else {
		// Otherwise, use the log level set by the Elastic Agent configuration.
		return cfgUpdate.agentLogLevel, nil
	}
}

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

		level, err := translate.LogpLevelToOTel(cfgUpdate.agentLogLevel)
		if err != nil {
			return nil, fmt.Errorf("failed to translate log level: %s", cfgUpdate.agentLogLevel)
		}

		if err := componentOtelCfg.Merge(confmap.NewFromStringMap(map[string]any{"service::telemetry::logs::level": level})); err != nil {
			return nil, fmt.Errorf("failed to set log level in otel config: %w", err)
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

		if mCfg := cfgUpdate.monitoringCfg; mCfg != nil {
			if mCfg.Enabled && mCfg.MonitorMetrics {
				// Metrics monitoring is enabled, inject a receiver for the
				// collector's internal telemetry.
				err := injectMonitoringReceiver(mergedOtelCfg, mCfg, agentInfo, cfgUpdate.components)
				if err != nil {
					return nil, fmt.Errorf("merging internal telemetry config: %w", err)
				}
			}
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

func monitoringEventTemplate(monitoring *monitoringCfg.MonitoringConfig, agentInfo info.Agent) map[string]any {
	namespace := "default"
	if monitoring.Namespace != "" {
		namespace = monitoring.Namespace
	}
	return map[string]any{
		"data_stream": map[string]any{
			"dataset":   "elastic_agent.elastic_agent",
			"namespace": namespace,
			"type":      "metrics",
		},
		"event": map[string]any{
			"dataset": "elastic_agent.elastic_agent",
		},
		"elastic_agent": map[string]any{
			"id":       agentInfo.AgentID(),
			"process":  "elastic-otel-collector",
			"snapshot": agentInfo.Snapshot(),
			"version":  agentInfo.Version(),
		},
		"agent": mapstr.M{
			"id": agentInfo.AgentID(),
		},
		"component": mapstr.M{
			"binary": "elastic-otel-collector",
			"id":     "elastic-otel-collector",
		},
		"metricset": mapstr.M{
			"name": "stats",
		},
	}
}

// exporterIDToOutputNameLookup compiles the mapping from raw collector
// exporter IDs to the policy output names that generated them, so internal
// telemetry monitoring can associate metrics with the user-defined name.
func exporterIDToOutputNameLookup(components []component.Component) (map[string]string, error) {
	lookup := map[string]string{}
	for _, comp := range components {
		exporterType, err := translate.OutputTypeToExporterType(comp.OutputType)
		if err != nil {
			return nil, err
		}
		exporterID := translate.GetExporterID(exporterType, comp.OutputName)
		// There may be collisions since multiple components can be generated
		// from the same output, but this is fine since they will all have
		// the same name as well.
		lookup[exporterID.String()] = fmt.Sprintf("%v-%v", exporterType, comp.OutputName)
	}
	return lookup, nil
}

func injectMonitoringReceiver(
	config *confmap.Conf,
	monitoring *monitoringCfg.MonitoringConfig,
	agentInfo info.Agent,
	components []component.Component,
) error {
	receiverType := otelcomponent.MustNewType(elasticmonitoringreceiver.Name)
	receiverName := "collector/internal-telemetry-monitoring"
	receiverID := translate.GetReceiverID(receiverType, receiverName).String()
	pipelineID := "logs/" + translate.OtelNamePrefix + receiverName
	exporterType := otelcomponent.MustNewType("elasticsearch")
	exporterID := translate.GetExporterID(exporterType, componentmonitoring.MonitoringOutput).String()
	monitoringExporterFound := false
	if config.IsSet("exporters") {
		// Search the defined exporters for one with the expected id for monitoring
		for exporter := range config.Get("exporters").(map[string]any) {
			if exporter == exporterID {
				monitoringExporterFound = true
			}
		}
	}
	if !monitoringExporterFound {
		// We can't monitor OTel metrics without OTel-based monitoring
		return nil
	}
	outputNameLookup, err := exporterIDToOutputNameLookup(components)
	if err != nil {
		return fmt.Errorf("couldn't map exporter IDs to output names: %w", err)
	}
	receiverCfg := map[string]any{
		"receivers": map[string]any{
			receiverID: map[string]any{
				"event_template": monitoringEventTemplate(monitoring, agentInfo),
				"interval":       monitoring.MetricsPeriod,
				"exporter_names": outputNameLookup,
			},
		},
		"service": map[string]any{
			"pipelines": map[string]any{
				pipelineID: map[string]any{
					"receivers": []string{receiverID},
					"exporters": []string{exporterID},
				},
			},
		},
	}
	return config.Merge(confmap.NewFromStringMap(receiverCfg))
}

func (m *OTelManager) applyMergedConfig(ctx context.Context,
	collectorStatusCh chan *status.AggregateStatus,
	collectorRunErr chan error,
	forceFetchStatusCh chan struct{},
) error {
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
		proc, err := m.execution.startCollector(ctx, m.collectorLogLevel, m.collectorLogger,
			m.managerLogger, m.mergedCollectorCfg, collectorRunErr, collectorStatusCh, forceFetchStatusCh)
		if err != nil {
			// failed to create the collector (this is different then
			// it's failing to run). we do not retry creation on failure
			// as it will always fail. A new configuration is required for
			// it not to fail (a new configuration will result in the retry)
			// since this is a new configuration we want to start the timer
			// from the initial delay
			recoveryDelay := m.recoveryTimer.ResetInitial()
			m.managerLogger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
			return err
		} else {
			// all good at the moment (possible that it will fail)
			m.proc = proc
		}
	}
	return nil
}

// Update sends collector configuration and component updates to the manager's run loop.
func (m *OTelManager) Update(cfg *confmap.Conf, monitoring *monitoringCfg.MonitoringConfig, ll logp.Level, components []component.Component) {
	cfgUpdate := configUpdate{
		collectorCfg:  cfg,
		monitoringCfg: monitoring,
		components:    components,
		agentLogLevel: ll,
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
	// Remove agent managed extensions from the status report
	if otelStatus != nil {
		if extensionsMap, exists := otelStatus.ComponentStatusMap["extensions"]; exists {
			for extensionKey := range extensionsMap.ComponentStatusMap {
				switch {
				case strings.HasPrefix(extensionKey, "extension:beatsauth"):
					delete(extensionsMap.ComponentStatusMap, extensionKey)
				case strings.HasPrefix(extensionKey, "extension:elastic_diagnostics"):
					delete(extensionsMap.ComponentStatusMap, extensionKey)
				case extensionKey == m.healthCheckExtID:
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

// reportStartupErr maps this error to the *status.AggregateStatus.
// this is done by parsing the `m.mergedCollectorCfg` and converting it into the best effort *status.AggregateStatus.
func (m *OTelManager) reportStartupErr(ctx context.Context, err error) {
	criticalErr := func(err error) error {
		otelStatus, err := otelConfigToStatus(m.mergedCollectorCfg, err)
		if err != nil {
			return err
		}
		return m.reportOtelStatusUpdate(ctx, otelStatus)
	}(err)
	if criticalErr != nil {
		// critical error occurred
		reportErr(ctx, m.errCh, fmt.Errorf("failed to report statup error: %w", criticalErr))
	} else {
		// no error reporting (clear critical)
		reportErr(ctx, m.errCh, nil)
	}
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
	case <-ctx.Done():
		// Manager is shutting down, ignore the update
		return
	}
}

// calculateConfmapHash calculates a hash of a given configuration. It's optimized for speed, which is why it
// json encodes the values directly into a xxhash instance, instead of converting to a map[string]any first.
func calculateConfmapHash(conf *confmap.Conf) ([]byte, error) {
	if conf == nil {
		return nil, nil
	}

	h := fnv.New128()
	// We encode the configuration to json instead of yaml, because it's simpler and more performant.
	// In general otel configuration can be marshalled to any format supported by koanf, but the confmap
	// API doesn't expose this. This is why the small workaround below to avoid converting to a Go map is necessary.
	encoder := json.NewEncoder(h)

	for _, key := range conf.AllKeys() { // this is a sorted list, so the output is consistent
		if err := encoder.Encode(key); err != nil {
			return nil, err
		}
		if err := encoder.Encode(conf.Get(key)); err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

func addCollectorMetricsReader(conf *confmap.Conf) error {
	// We operate on untyped maps instead of otel config structs because the otel collector has an elaborate
	// configuration resolution system, and we can't reproduce it fully here. It's possible some of the values won't
	// be valid for unmarshalling, because they're supposed to be loaded from environment variables, and so on.
	metricReadersUntyped := conf.Get("service::telemetry::metrics::readers")
	if metricReadersUntyped == nil {
		metricReadersUntyped = []any{}
	}
	metricsReadersList, ok := metricReadersUntyped.([]any)
	if !ok {
		return fmt.Errorf("couldn't convert value of service::telemetry::metrics::readers to a list: %v", metricReadersUntyped)
	}

	metricsReader := map[string]any{
		"pull": map[string]any{
			"exporter": map[string]any{
				"prometheus": map[string]any{
					"host": "localhost",
					// The OTel manager is required to set this environment variable. See comment at the constant
					// definition for more information.
					"port": fmt.Sprintf("${env:%s}", OtelCollectorMetricsPortEnvVarName),
					// this is the default configuration from the otel collector
					"without_scope_info":  true,
					"without_units":       true,
					"without_type_suffix": true,
				},
			},
		},
	}
	metricsReadersList = append(metricsReadersList, metricsReader)
	confMap := map[string]any{
		"service::telemetry::metrics::readers": metricsReadersList,
	}
	if mergeErr := conf.Merge(confmap.NewFromStringMap(confMap)); mergeErr != nil {
		return fmt.Errorf("failed to merge config: %w", mergeErr)
	}
	return nil
}
