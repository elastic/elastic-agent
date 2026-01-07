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

<<<<<<< HEAD
=======
const (
	// CollectorStopTimeout is the duration to wait for the collector to stop. Note: this needs to be shorter
	// than 5 * time.Second (coordinator.managerShutdownTimeout) otherwise we might end up with a defunct process.
	CollectorStopTimeout = 3 * time.Second
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
	logLevel      logp.Level
}

>>>>>>> 85b7e9932 ((bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used (#11998))
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
<<<<<<< HEAD
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
=======

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
	logLevel string
}

// NewOTelManager returns a OTelManager.
func NewOTelManager(
	logger *logger.Logger,
	logLevel logp.Level,
	baseLogger *logger.Logger,
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
		logger:                     logger,
		baseLogger:                 baseLogger,
		agentInfo:                  agentInfo,
		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
		healthCheckExtID:           fmt.Sprintf("extension:healthcheckv2/%s", hcUUIDStr),
		errCh:                      make(chan error, 1), // holds at most one error
		collectorStatusCh:          make(chan *status.AggregateStatus, 1),
		// componentStateCh uses a buffer channel to ensure that no state transitions are missed and to prevent
		// any possible case of deadlock, 5 is used just to give a small buffer.
		componentStateCh: make(chan []runtime.ComponentComponentState, 5),
		updateCh:         make(chan configUpdate, 1),
		doneChan:         make(chan struct{}),
		execution:        exec,
		recoveryTimer:    recoveryTimer,
		collectorRunErr:  make(chan error),
		stopTimeout:      stopTimeout,
		logLevel:         logLevel.String(),
	}, nil
>>>>>>> 85b7e9932 ((bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used (#11998))
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

			// at this point no critical errors are occurring
			// any issues starting the collector are reporting in the status
			reportErr(ctx, m.errCh, nil)

			newRetries := m.recoveryRetries.Add(1)
			m.logger.Infof("collector recovery restarting, total retries: %d", newRetries)
			m.proc, err = m.execution.startCollector(ctx, m.logLevel, m.baseLogger, m.logger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh, forceFetchStatusCh)
			if err != nil {
				// report a startup error (this gets reported as status)
				m.reportStartupErr(ctx, err)
				// reset the restart timer to the next backoff
				recoveryDelay := m.recoveryTimer.ResetNext()
				m.logger.Errorf("collector exited with error (will try to recover in %s): %v", recoveryDelay.String(), err)
			}
		case err = <-m.collectorRunErr:
			m.recoveryTimer.Stop()
>>>>>>> 85b7e9932 ((bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used (#11998))
			if err == nil {
				// err is nil but there is a configuration
				//
				// in this rare case the collector stopped running but a configuration was
				// provided and the collector stopped with a clean exit
<<<<<<< HEAD
				cancel()
				cancel, provider, err = m.startCollector(m.cfg, runErrCh)
=======
				m.proc, err = m.execution.startCollector(ctx, m.logLevel, m.baseLogger, m.logger, m.mergedCollectorCfg, m.collectorRunErr, collectorStatusCh, forceFetchStatusCh)
>>>>>>> 85b7e9932 ((bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used (#11998))
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
=======

		case cfgUpdate := <-m.updateCh:
			// we received a new configuration, thus stop the recovery timer
			// and reset the retry count
			m.recoveryTimer.Stop()
			m.recoveryRetries.Store(0)
			mergedCfg, err := buildMergedConfig(cfgUpdate, m.agentInfo, m.beatMonitoringConfigGetter, m.baseLogger)
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
			// set the log level defined in service::telemetry::log::level setting
			if mergedCfg != nil && mergedCfg.IsSet("service::telemetry::logs::level") {
				if logLevel, ok := mergedCfg.Get("service::telemetry::logs::level").(string); ok {
					m.logLevel = logLevel
				} else {
					m.logger.Warn("failed to access log level from service::telemetry::logs::level")
				}
			} else {
				// when mergedCfg is nil use coordinator's log level
				m.logLevel = cfgUpdate.logLevel.String()
			}
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
>>>>>>> 85b7e9932 ((bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used (#11998))
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

		level := translate.GetOTelLogLevel(cfgUpdate.logLevel.String())
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
				err := injectMonitoringReceiver(mergedOtelCfg, mCfg, agentInfo)
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
			"process":  "elastic-agent",
			"snapshot": agentInfo.Snapshot(),
			"version":  agentInfo.Version(),
		},
		"agent": mapstr.M{
			"id": agentInfo.AgentID(),
		},
		"component": mapstr.M{
			"binary": "elastic-agent",
			"id":     "elastic-agent/collector",
		},
		"metricset": mapstr.M{
			"name": "stats",
		},
	}
}

func injectMonitoringReceiver(
	config *confmap.Conf,
	monitoring *monitoringCfg.MonitoringConfig,
	agentInfo info.Agent,
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
	receiverCfg := map[string]any{
		"receivers": map[string]any{
			receiverID: map[string]any{
				"event_template": monitoringEventTemplate(monitoring, agentInfo),
				"interval":       monitoring.MetricsPeriod,
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
		proc, err := m.execution.startCollector(ctx, m.logLevel, m.baseLogger, m.logger, m.mergedCollectorCfg, collectorRunErr, collectorStatusCh, forceFetchStatusCh)
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
func (m *OTelManager) Update(cfg *confmap.Conf, monitoring *monitoringCfg.MonitoringConfig, ll logp.Level, components []component.Component) {
	cfgUpdate := configUpdate{
		collectorCfg:  cfg,
		monitoringCfg: monitoring,
		components:    components,
		logLevel:      ll,
	}

	// we care only about the latest config update
>>>>>>> 85b7e9932 ((bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used (#11998))
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
	case m.errCh <- err:
	case <-ctx.Done():
	}
}
