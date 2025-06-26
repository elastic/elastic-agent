// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

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
	ResetInitial()
	// ResetNext resets the timer to the next interval
	ResetNext()
	// C returns the timer channel
	C() <-chan time.Time
}

// OTelManager is a manager that manages the lifecycle of the OTel collector inside of the Elastic Agent.
type OTelManager struct {
	// baseLogger is the base logger for the otel collector, and doesn't include any agent-specific fields.
	baseLogger *logger.Logger
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

	// recoveryTimer is used to restart the collector when it has errored.
	recoveryTimer collectorRecoveryTimer

	// recoveryRetries is the number of times the collector has been
	// restarted through the recovery timer.
	recoveryRetries uint32

	// execution is used to invoke the collector into different execution modes
	execution collectorExecution
}

// NewOTelManager returns a OTelManager.
func NewOTelManager(logger *logger.Logger, logLevel logp.Level, baseLogger *logger.Logger, mode ExecutionMode) (*OTelManager, error) {
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
		recoveryTimer = newRecoveryBackoff(time.Second, 10*time.Second)
		exec = newSubprocessExecution(logLevel, executable)
	case EmbeddedExecutionMode:
		recoveryTimer = newRestarterNoop()
		exec = newExecutionEmbedded()
	default:
		return nil, errors.New("unknown otel collector exec")
	}

	logger.Debugf("Using collector execution mode: %s", mode)

	return &OTelManager{
		logger:        logger,
		baseLogger: baseLogger,
		errCh:         make(chan error, 1), // holds at most one error
		cfgCh:         make(chan *confmap.Conf),
		statusCh:      make(chan *status.AggregateStatus),
		doneChan:      make(chan struct{}),
		execution:     exec,
		recoveryTimer: recoveryTimer,
	}, nil
}

// Run runs the lifecycle of the manager.
func (m *OTelManager) Run(ctx context.Context) error {
	var (
		err  error
		proc collectorHandle
	)

	// signal that the run loop is ended to unblock any incoming update calls
	defer close(m.doneChan)

	// collectorRunErr is used to signal that the collector has exited.
	collectorRunErr := make(chan error)
	for {
		select {
		case <-ctx.Done():
			m.recoveryTimer.Stop()
			// our caller context is cancelled so stop the collector and return
			// has exited.
			if proc != nil {
				proc.Stop(ctx)
			}
			return ctx.Err()
		case <-m.recoveryTimer.C():
			m.recoveryTimer.Stop()

			if m.cfg == nil || proc != nil || ctx.Err() != nil {
				// no configuration, or the collector is already running, or the context
				// is cancelled.
				continue
			}

			m.recoveryRetries++
			m.logger.Infof("collector recovery restarting, total retries: %d", m.recoveryRetries)
			proc, err = m.execution.startCollector(ctx, m.logger, m.cfg, collectorRunErr, m.statusCh)
			if err != nil {
				m.logger.Errorf("collector exited with error: %v", err)
				reportErr(ctx, m.errCh, err)
				// reset the restart timer to the next backoff
				m.recoveryTimer.ResetNext()
			} else {
				reportErr(ctx, m.errCh, nil)
			}

		case err = <-collectorRunErr:
			m.recoveryTimer.Stop()
			if err == nil {
				// err is nil means that the collector has exited cleanly without an error
				if proc != nil {
					proc.Stop(ctx)
					proc = nil
					reportStatus(ctx, m.statusCh, nil)
				}

				if m.cfg == nil {
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
				proc, err = m.execution.startCollector(ctx, m.logger, m.cfg, collectorRunErr, m.statusCh)
				if err != nil {
					m.logger.Errorf("collector exited with error: %v", err)
					// failed to create the collector (this is different then
					// it's failing to run). we do not retry creation on failure
					// as it will always fail. A new configuration is required for
					// it not to fail (a new configuration will result in the retry)
					reportErr(ctx, m.errCh, err)
					// reset the restart timer to the next backoff
					m.recoveryTimer.ResetNext()
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
				if proc != nil {
					proc.Stop(ctx)
					proc = nil
					// don't wait here for <-collectorRunErr, already occurred
					// clear status, no longer running
					reportStatus(ctx, m.statusCh, nil)
				}
				// pass the error to the errCh so the coordinator, unless it's a cancel error
				if !errors.Is(err, context.Canceled) {
					m.logger.Errorf("collector exited with error: %v", err)
					reportErr(ctx, m.errCh, err)
					// reset the restart timer to the next backoff
					m.recoveryTimer.ResetNext()
				}
			}

		case cfg := <-m.cfgCh:
			// we received a new configuration, thus stop the recovery timer
			// and reset the retry count
			m.recoveryTimer.Stop()
			m.recoveryRetries = 0
			m.cfg = cfg

			if proc != nil {
				proc.Stop(ctx)
				proc = nil
				select {
				case <-collectorRunErr:
				case <-ctx.Done():
					// our caller ctx is Done
					return ctx.Err()
				}
				reportStatus(ctx, m.statusCh, nil)
			}

			if cfg == nil {
				// no configuration then the collector should not be
				// running.
				// ensure that the coordinator knows that there is no error
				// as the collector is not running anymore
				reportErr(ctx, m.errCh, nil)
			} else {
				// either a new configuration or the first configuration
				// that results in the collector being started
				proc, err = m.execution.startCollector(ctx, m.logger, m.cfg, collectorRunErr, m.statusCh)
				if err != nil {
					m.logger.Errorf("collector exited with error: %v", err)
					// failed to create the collector (this is different then
					// it's failing to run). we do not retry creation on failure
					// as it will always fail. A new configuration is required for
					// it not to fail (a new configuration will result in the retry)
					reportErr(ctx, m.errCh, err)
					// since this is a new configuration we want to start the timer
					// from the initial delay
					m.recoveryTimer.ResetInitial()
				} else {
					// all good at the moment (possible that it will fail)
					reportErr(ctx, m.errCh, nil)
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
