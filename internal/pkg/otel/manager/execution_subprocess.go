// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"

	runtimeLogger "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

const (
	processKillAfter = 5 * time.Second

	OtelSetSupervisedFlagName          = "supervised"
	OtelSupervisedLoggingLevelFlagName = "supervised.logging.level"
)

func newSubprocessExecution(logLevel logp.Level, collectorPath string) *subprocessExecution {
	return &subprocessExecution{
		collectorPath: collectorPath,
		collectorArgs: []string{
			"otel",
			fmt.Sprintf("--%s", OtelSetSupervisedFlagName),
			fmt.Sprintf("--%s=%s", OtelSupervisedLoggingLevelFlagName, logLevel.String()),
		},
		logLevel: logLevel,
	}
}

type subprocessExecution struct {
	collectorPath string
	collectorArgs []string
	logLevel      logp.Level
}

// startCollector starts a supervised collector and monitors its health. Process exit errors are sent to the
// processErrCh channel. Other run errors, such as not able to connect to the health endpoint, are sent to the runErrCh channel.
func (r *subprocessExecution) startCollector(ctx context.Context, logger *logger.Logger, cfg *confmap.Conf, processErrCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error) {
	if cfg == nil {
		// configuration is required
		return nil, errors.New("no configuration provided")
	}

	if r.collectorPath == "" {
		// collector path is required
		return nil, errors.New("no collector path provided")
	}

	if _, err := os.Stat(r.collectorPath); err != nil {
		// we cannot access the collector path
		return nil, fmt.Errorf("cannot access collector path: %w", err)
	}

	httpHealthCheckPort, err := findRandomTCPPort()
	if err != nil {
		return nil, fmt.Errorf("could not find port for http health check: %w", err)
	}

	if err := injectHeathCheckV2Extension(cfg, httpHealthCheckPort); err != nil {
		return nil, fmt.Errorf("failed to inject health check extension: %w", err)
	}

	confMap := cfg.ToStringMap()
	confBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	stdOut := runtimeLogger.NewLogWriterWithDefaults(logger.Core(), zapcore.Level(r.logLevel))
	// info level for stdErr because by default collector writes to stderr
	stdErr := runtimeLogger.NewLogWriterWithDefaults(logger.Core(), zapcore.Level(r.logLevel))

	procCtx, procCtxCancel := context.WithCancel(ctx)
	processInfo, err := process.Start(r.collectorPath,
		process.WithArgs(r.collectorArgs),
		process.WithContext(procCtx),
		process.WithEnv(os.Environ()),
		process.WithCmdOptions(func(c *exec.Cmd) error {
			c.Stdin = bytes.NewReader(confBytes)
			c.Stdout = stdOut
			c.Stderr = stdErr
			return nil
		}),
	)
	if err != nil {
		// we failed to start the process
		procCtxCancel()
		return nil, fmt.Errorf("failed to start supervised collector: %w", err)
	}
	logger.Infof("supervised collector started with pid: %d and healthcheck port: %d", processInfo.Process.Pid, httpHealthCheckPort)
	if processInfo.Process == nil {
		// this should not happen but just in case
		procCtxCancel()
		return nil, fmt.Errorf("failed to start supervised collector: process is nil")
	}

	ctl := &procHandle{
		processDoneCh: make(chan struct{}),
		processInfo:   processInfo,
	}

	healthCheckDone := make(chan struct{})
	go func() {
		defer func() {
			close(healthCheckDone)
		}()
		currentStatus := aggregateStatus(componentstatus.StatusStarting, nil)
		reportCollectorStatus(ctx, statusCh, currentStatus)

		// specify a max duration of not being able to get the status from the collector
		const maxFailuresDuration = 130 * time.Second
		maxFailuresTimer := time.NewTimer(maxFailuresDuration)
		defer maxFailuresTimer.Stop()

		// check the health of the collector every 1 second
		const healthCheckPollDuration = 1 * time.Second
		healthCheckPollTimer := time.NewTimer(healthCheckPollDuration)
		defer healthCheckPollTimer.Stop()
		for {
			statuses, err := AllComponentsStatuses(procCtx, httpHealthCheckPort)
			if err != nil {
				switch {
				case errors.Is(err, context.Canceled):
					reportCollectorStatus(ctx, statusCh, aggregateStatus(componentstatus.StatusStopped, nil))
					return
				}
			} else {
				maxFailuresTimer.Reset(maxFailuresDuration)

				if !compareStatuses(currentStatus, statuses) {
					currentStatus = statuses
					reportCollectorStatus(procCtx, statusCh, statuses)
				}
			}

			select {
			case <-procCtx.Done():
				reportCollectorStatus(ctx, statusCh, aggregateStatus(componentstatus.StatusStopped, nil))
				return
			case <-healthCheckPollTimer.C:
				healthCheckPollTimer.Reset(healthCheckPollDuration)
			case <-maxFailuresTimer.C:
				failedToConnectStatuses := aggregateStatus(
					componentstatus.StatusRecoverableError,
					errors.New("failed to connect to collector"),
				)
				if !compareStatuses(currentStatus, failedToConnectStatuses) {
					currentStatus = statuses
					reportCollectorStatus(procCtx, statusCh, statuses)
				}
			}
		}
	}()

	go func() {
		procState, procErr := processInfo.Process.Wait()
		procCtxCancel()
		<-healthCheckDone
		close(ctl.processDoneCh)
		// using ctx instead of procCtx in the reportErr functions below is intentional. This allows us to report
		// errors to the caller through processErrCh and essentially discard any other errors that occurred because
		// the process exited.
		if procErr == nil {
			if procState.Success() {
				// report nil error so that the caller can be notified that the process has exited without error
				reportErr(ctx, processErrCh, nil)
			} else {
				reportErr(ctx, processErrCh, fmt.Errorf("supervised collector (pid: %d) exited with error: %s", procState.Pid(), procState.String()))
			}
			return
		}

		reportErr(ctx, processErrCh, fmt.Errorf("failed to wait supervised collector process: %w", procErr))
	}()

	return ctl, nil
}

type procHandle struct {
	processDoneCh chan struct{}
	processInfo   *process.Info
}

// Stop stops the process. If the process is already stopped, it does nothing. If the process does not stop within
// processKillAfter or due to an error, it will be killed.
func (s *procHandle) Stop(ctx context.Context) {
	select {
	case <-s.processDoneCh:
		// process has already exited
		return
	default:
	}

	if err := s.processInfo.Stop(); err != nil {
		// we failed to stop the process just kill it and return
		_ = s.processInfo.Kill()
		return
	}

	select {
	case <-ctx.Done():
		// our caller ctx is Done; kill the process just in case
		_ = s.processInfo.Kill()
	case <-s.processDoneCh:
		// process has already exited
	case <-time.After(processKillAfter):
		// process is still running kill it
		_ = s.processInfo.Kill()
	}
}
