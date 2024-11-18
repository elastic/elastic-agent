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
		errCh:    make(chan error),
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
					// as it will always fail a new configuration is required for
					// it not to fail (a new configuration will result in the retry)
					select {
					case m.errCh <- err:
					case <-ctx.Done():
					}
				} else {
					// all good at the moment (possible that it will fail)
					select {
					case m.errCh <- nil:
					case <-ctx.Done():
					}
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
					select {
					case m.errCh <- nil:
					case <-ctx.Done():
					}
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
				select {
				case m.errCh <- nil:
				case <-ctx.Done():
				}
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
						// as it will always fail a new configuration is required for
						// it not to fail (a new configuration will result in the retry)
						select {
						case m.errCh <- err:
						case <-ctx.Done():
						}
					} else {
						// all good at the moment (possible that it will fail)
						select {
						case m.errCh <- nil:
						case <-ctx.Done():
						}
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
