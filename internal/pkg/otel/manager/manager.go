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
			m.mergedCollectorCfg = mergedCfg
			m.collectorCfg = cfgUpdate.collectorCfg
			m.components = cfgUpdate.components
			m.mx.Unlock()

			err = m.applyMergedConfig(ctx, collectorStatusCh, collectorRunErr)
			// report the error unconditionally to indicate that the config was applied
			reportErr(ctx, m.errCh, err)

		case otelStatus := <-collectorStatusCh:
			err = m.reportOtelStatusUpdate(ctx, otelStatus)
			if err != nil {
				reportErr(ctx, m.errCh, err)
>>>>>>> 779fafdcd ([beatreceivers] Integrate beatsauthextension (#9257))
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
		m.proc.Stop(ctx)
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
>>>>>>> 779fafdcd ([beatreceivers] Integrate beatsauthextension (#9257))
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
	case <-m.errCh:
	default:
	}
	select {
	case m.errCh <- err:
	case <-ctx.Done():
	}
}
