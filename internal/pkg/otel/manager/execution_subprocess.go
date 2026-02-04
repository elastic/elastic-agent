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
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"gopkg.in/yaml.v3"

	otelstatus "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/otel/status"
	runtimeLogger "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

const (
	OtelSetSupervisedFlagName                 = "supervised"
	OtelSupervisedLoggingLevelFlagName        = "supervised.logging.level"
	OtelSupervisedMonitoringURLFlagName       = "supervised.monitoring.url"
	OtelFeatureGatesFlagName                  = "feature-gates"
	OtelElasticsearchExporterTelemetryFeature = "telemetry.newPipelineTelemetry"
)

// newSubprocessExecution creates a new execution which runs the otel collector in a subprocess. A metricsPort or
// healthCheckPort of 0 will result in a random port being used.
func newSubprocessExecution(collectorPath string, uuid string, metricsPort int, healthCheckPort int) (*subprocessExecution, error) {
	componentType, err := component.NewType(healthCheckExtensionName)
	if err != nil {
		return nil, fmt.Errorf("cannot create component type: %w", err)
	}
	healthCheckExtensionID := component.NewIDWithName(componentType, uuid).String()

	return &subprocessExecution{
		collectorPath: collectorPath,
		collectorArgs: []string{
			fmt.Sprintf("--%s", OtelSetSupervisedFlagName),
			fmt.Sprintf("--%s=%s", OtelSupervisedMonitoringURLFlagName, monitoring.EDOTMonitoringEndpoint()),
			// Enable feature gate to report internal telemetry for the Elasticsearch exporter partitioned
			// by the exporter instance (e.g. separating the monitoring exporter from general inputs),
			// matching the behavior of other Collector telemetry metrics like queue state.
			fmt.Sprintf("--%s=%s", OtelFeatureGatesFlagName, OtelElasticsearchExporterTelemetryFeature),
		},
		healthCheckExtensionID:   healthCheckExtensionID,
		collectorMetricsPort:     metricsPort,
		collectorHealthCheckPort: healthCheckPort,
		reportErrFn:              reportErr,
	}, nil
}

// subprocessExecution implements collectorExecution by running the collector in a subprocess.
type subprocessExecution struct {
	collectorPath            string
	collectorArgs            []string
	healthCheckExtensionID   string
	collectorMetricsPort     int
	collectorHealthCheckPort int
	reportErrFn              func(ctx context.Context, errCh chan error, err error) // required for testing
}

// startCollector starts a supervised collector and monitors its health. Process exit errors are sent to the
// processErrCh channel. Other run errors, such as not able to connect to the health endpoint, are sent to the runErrCh channel.
func (r *subprocessExecution) startCollector(
	ctx context.Context,
	lvl logp.Level,
	collectorLogger *logger.Logger,
	logger *logger.Logger,
	cfg *confmap.Conf,
	processErrCh chan error,
	statusCh chan *otelstatus.AggregateStatus,
	forceFetchStatusCh chan struct{},
) (collectorHandle, error) {
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

	httpHealthCheckPort, collectorMetricsPort, err := r.getCollectorPorts()
	if err != nil {
		return nil, fmt.Errorf("could not find port for collector: %w", err)
	}

	if err := injectHealthCheckV2Extension(cfg, r.healthCheckExtensionID, httpHealthCheckPort); err != nil {
		return nil, fmt.Errorf("failed to inject health check extension: %w", err)
	}

	confMap := cfg.ToStringMap()
	confBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	stdOutLast := newZapLast(collectorLogger.Core())
	stdOut := runtimeLogger.NewLogWriterWithDefaults(stdOutLast, zapcore.Level(lvl))
	// info level for stdErr because by default collector writes to stderr
	stdErrLast := newZapLast(collectorLogger.Core())
	stdErr := runtimeLogger.NewLogWriterWithDefaults(stdErrLast, zapcore.Level(lvl))

	procCtx, procCtxCancel := context.WithCancel(ctx)
	env := os.Environ()
	// Set the environment variable for the collector metrics port. See comment at the constant definition for more information.
	env = append(env, fmt.Sprintf("%s=%d", OtelCollectorMetricsPortEnvVarName, collectorMetricsPort))

	// set collector args
	collectorArgs := append(r.collectorArgs, fmt.Sprintf("--%s=%s", OtelSupervisedLoggingLevelFlagName, lvl))

	processInfo, err := process.Start(r.collectorPath,
		process.WithArgs(collectorArgs),
		process.WithEnv(env),
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
		log:           logger,
	}

	healthCheckDone := make(chan struct{})
	go func() {
		defer func() {
			close(healthCheckDone)
		}()
		currentStatus := status.AggregateStatus(componentstatus.StatusStarting, nil)
		r.reportSubprocessCollectorStatus(ctx, statusCh, currentStatus)

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
					// after the collector exits, we need to report a nil status
					r.reportSubprocessCollectorStatus(ctx, statusCh, nil)
					return
				default:
					// if we face any other error (most likely, connection refused), log the error.
					logger.Debugf("Received an unexpected error while fetching component status: %v", err)
				}
			} else {
				maxFailuresTimer.Reset(maxFailuresDuration)
				removeManagedHealthCheckExtensionStatus(statuses, r.healthCheckExtensionID)
				if !status.CompareStatuses(currentStatus, statuses) {
					currentStatus = statuses
					r.reportSubprocessCollectorStatus(procCtx, statusCh, statuses)
				}
			}

			select {
			case <-procCtx.Done():
				// after the collector exits, we need to report a nil status
				r.reportSubprocessCollectorStatus(ctx, statusCh, nil)
				return
			case <-forceFetchStatusCh:
				r.reportSubprocessCollectorStatus(procCtx, statusCh, statuses)
			case <-healthCheckPollTimer.C:
				healthCheckPollTimer.Reset(healthCheckPollDuration)
			case <-maxFailuresTimer.C:
				failedToConnectStatuses := status.AggregateStatus(
					componentstatus.StatusRecoverableError,
					errors.New("failed to connect to collector"),
				)
				if !status.CompareStatuses(currentStatus, failedToConnectStatuses) {
					currentStatus = statuses
					r.reportSubprocessCollectorStatus(procCtx, statusCh, statuses)
				}
			}
		}
	}()

	go func() {
		procState, procErr := processInfo.Process.Wait()
		logger.Debugf("wait for pid %d returned", processInfo.PID)
		procCtxCancel()
		<-healthCheckDone
		close(ctl.processDoneCh)
		// using ctx instead of procCtx in the reportErr functions below is intentional. This allows us to report
		// errors to the caller through processErrCh and essentially discard any other errors that occurred because
		// the process exited.
		if procErr == nil {
			if procState.Success() {
				// report nil error so that the caller can be notified that the process has exited without error
				r.reportErrFn(ctx, processErrCh, nil)
			} else {
				var procReportErr error
				stderrMsg := stdErrLast.Last().Message
				stdoutMsg := stdOutLast.Last().Message
				if stderrMsg != "" {
					// use stderr message as the error
					procReportErr = errors.New(stderrMsg)
				} else if stdoutMsg != "" {
					// use last stdout message as the error
					procReportErr = errors.New(stdoutMsg)
				} else {
					// neither case use standard process error
					procReportErr = fmt.Errorf("supervised collector (pid: %d) exited with error: %s", procState.Pid(), procState.String())
				}
				r.reportErrFn(ctx, processErrCh, procReportErr)
			}
			return
		}

		r.reportErrFn(ctx, processErrCh, fmt.Errorf("failed to wait supervised collector process: %w", procErr))
	}()

	return ctl, nil
}

// cloneCollectorStatus creates a deep copy of the provided AggregateStatus.
func cloneCollectorStatus(aStatus *otelstatus.AggregateStatus) *otelstatus.AggregateStatus {
	if aStatus == nil {
		return nil
	}

	st := &otelstatus.AggregateStatus{
		Event: aStatus.Event,
	}

	if len(aStatus.ComponentStatusMap) > 0 {
		st.ComponentStatusMap = make(map[string]*otelstatus.AggregateStatus, len(aStatus.ComponentStatusMap))
		for k, cs := range aStatus.ComponentStatusMap {
			st.ComponentStatusMap[k] = cloneCollectorStatus(cs)
		}
	}

	return st
}

func (r *subprocessExecution) reportSubprocessCollectorStatus(ctx context.Context, statusCh chan *otelstatus.AggregateStatus, collectorStatus *otelstatus.AggregateStatus) {
	// we need to clone the status to prevent any mutation on the receiver side
	// affecting the original ref
	clonedStatus := cloneCollectorStatus(collectorStatus)
	reportCollectorStatus(ctx, statusCh, clonedStatus)
}

// getCollectorPorts returns the ports used by the OTel collector. If the ports set in the execution struct are 0,
// random ports are returned instead.
func (r *subprocessExecution) getCollectorPorts() (healthCheckPort int, metricsPort int, err error) {
	randomPorts := make([]*int, 0, 2)
	// if the ports are defined (non-zero), use them
	if r.collectorMetricsPort == 0 {
		randomPorts = append(randomPorts, &metricsPort)
	} else {
		metricsPort = r.collectorMetricsPort
	}
	if r.collectorHealthCheckPort == 0 {
		randomPorts = append(randomPorts, &healthCheckPort)
	} else {
		healthCheckPort = r.collectorHealthCheckPort
	}

	if len(randomPorts) == 0 {
		return healthCheckPort, metricsPort, nil
	}

	// we need at least one random port, create it
	ports, err := findRandomTCPPorts(len(randomPorts))
	if err != nil {
		return 0, 0, err
	}
	for i, port := range ports {
		*randomPorts[i] = port
	}
	return healthCheckPort, metricsPort, nil
}

func removeManagedHealthCheckExtensionStatus(status *otelstatus.AggregateStatus, healthCheckExtensionID string) {
	extensions, exists := status.ComponentStatusMap["extensions"]
	if !exists {
		return
	}

	extensionID := "extension:" + healthCheckExtensionID
	delete(extensions.ComponentStatusMap, extensionID)
}

type procHandle struct {
	processDoneCh chan struct{}
	processInfo   *process.Info
	log           *logger.Logger
}

// Stop stops the process. If the process is already stopped, it does nothing. If the process does not stop within
// processKillAfter or due to an error, it will be killed.
func (s *procHandle) Stop(waitTime time.Duration) {
	select {
	case <-s.processDoneCh:
		// process has already exited
		return
	default:
	}

	s.log.Debugf("gracefully stopping pid %d", s.processInfo.PID)
	if err := s.processInfo.Stop(); err != nil {
		s.log.Warnf("failed to send stop signal to the supervised collector: %v", err)
		// we failed to stop the process just kill it and return
	} else {
		select {
		case <-time.After(waitTime):
			s.log.Warnf("timeout waiting (%s) for the supervised collector to stop, killing it", waitTime.String())
		case <-s.processDoneCh:
			// process has already exited
			return
		}
	}

	// since we are here this means that the process either got an error at stop or did not stop within the timeout,
	// kill it and give one more mere second for the process wait to be called
	_ = s.processInfo.Kill()
	select {
	case <-time.After(1 * time.Second):
		s.log.Warnf("supervised collector subprocess didn't exit in time after killing it")
	case <-s.processDoneCh:
	}
}

type zapWriter interface {
	Write(zapcore.Entry, []zapcore.Field) error
}
type zapLast struct {
	wrapped zapWriter
	last    zapcore.Entry
	mx      sync.Mutex
}

func newZapLast(w zapWriter) *zapLast {
	return &zapLast{
		wrapped: w,
	}
}

// Write stores the most recent log entry.
func (z *zapLast) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	z.mx.Lock()
	z.last = entry
	z.mx.Unlock()
	return z.wrapped.Write(entry, fields)
}

// Last returns the last log entry.
func (z *zapLast) Last() zapcore.Entry {
	z.mx.Lock()
	defer z.mx.Unlock()
	return z.last
}
