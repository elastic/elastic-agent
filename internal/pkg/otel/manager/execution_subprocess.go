// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	otelstatus "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/otel/status"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

const (
	OtelSetSupervisedFlagName                 = "supervised"
	OtelSupervisedLoggingLevelFlagName        = "supervised.logging.level"
	OtelSupervisedMonitoringURLFlagName       = "supervised.monitoring.url"
	OtelFeatureGatesFlagName                  = "feature-gates"
	OtelElasticsearchExporterTelemetryFeature = "telemetry.newPipelineTelemetry"

	// agentConfigProviderScheme must match agentprovider.AgentConfigProviderSchemeName.
	// Duplicated here to avoid a cross-module import from the main module into
	// the internal/edot submodule.
	agentConfigProviderScheme = "elasticagent"
)

// newSubprocessExecution creates a new execution which runs the otel collector in a subprocess.
// A healthCheckPort of 0 will result in a random port being used. A metricsPort of 0 means the
// collector will pick a random port at startup.
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

	httpHealthCheckPort, err := r.getCollectorHealthCheckPort()
	if err != nil {
		return nil, fmt.Errorf("could not find port for collector: %w", err)
	}

	if err := addCollectorMetricsReader(cfg, r.collectorMetricsPort); err != nil {
		return nil, fmt.Errorf("failed to add collector metrics reader: %w", err)
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
	stdOut := runtime.NewLogWriterWithDefaults(stdOutLast, zapcore.Level(lvl))
	// info level for stdErr because by default collector writes to stderr
	stdErrLast := newZapLast(collectorLogger.Core())
	stdErr := runtime.NewLogWriterWithDefaults(stdErrLast, zapcore.Level(lvl))

	procCtx, procCtxCancel := context.WithCancel(ctx)
	env := os.Environ()

	// Generate a unique socket URL for config streaming
	sockUUID, err := uuid.NewV4()
	if err != nil {
		procCtxCancel()
		return nil, fmt.Errorf("failed to generate socket UUID: %w", err)
	}
	sockURL := paths.OtelConfigSocket(sockUUID.String())

	// Create listener for config streaming socket
	lis, err := ipc.CreateListener(logger, sockURL)
	if err != nil {
		procCtxCancel()
		return nil, fmt.Errorf("failed to create config socket listener: %w", err)
	}

	// set collector args and add --config flag with the elasticagent:<socketURL> URI
	collectorArgs := append(r.collectorArgs, fmt.Sprintf("--%s=%s", OtelSupervisedLoggingLevelFlagName, lvl))
	collectorArgs = append(collectorArgs, fmt.Sprintf("--config=%s:%s", agentConfigProviderScheme, sockURL))

	processInfo, err := process.Start(r.collectorPath,
		process.WithArgs(collectorArgs),
		process.WithEnv(env),
		process.WithCmdOptions(func(c *exec.Cmd) error {
			c.Stdout = stdOut
			c.Stderr = stdErr
			return nil
		}),
	)
	if err != nil {
		// we failed to start the process
		_ = lis.Close()
		ipc.CleanupListener(logger, sockURL)
		procCtxCancel()
		return nil, fmt.Errorf("failed to start supervised collector: %w", err)
	}

	logger.Infof("supervised collector started with pid: %d and healthcheck port: %d", processInfo.Process.Pid, httpHealthCheckPort)
	if processInfo.Process == nil {
		// this should not happen but just in case
		_ = lis.Close()
		ipc.CleanupListener(logger, sockURL)
		procCtxCancel()
		return nil, fmt.Errorf("failed to start supervised collector: process is nil")
	}

	ctl := newProcHandle(processInfo, logger, nil)

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
		client := http.Client{}
		for {
			statuses, err := AllComponentsStatuses(procCtx, client, httpHealthCheckPort)
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

	// Accept connection from subprocess (with cancellation if process dies).
	// The monitoring goroutines are already running so that even if the process
	// dies before connecting, its exit is properly reported.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := lis.Accept()
		acceptCh <- acceptResult{conn: conn, err: err}
	}()

	select {
	case <-procCtx.Done():
		// Process died before connecting. Close the listener to unblock Accept.
		_ = lis.Close()
		ipc.CleanupListener(logger, sockURL)
		// The process monitoring goroutines are already running and will report
		// the exit error. Return the handle so the caller can observe the exit.
		return ctl, nil
	case result := <-acceptCh:
		// Close the listener and clean up the socket file; we only need one connection
		_ = lis.Close()
		ipc.CleanupListener(logger, sockURL)
		if result.err != nil {
			// Accept failed (e.g. listener was closed because process died).
			// If the process context is done, the monitoring goroutines handle it.
			if procCtx.Err() != nil {
				return ctl, nil //nolint: nilerr // if there's a problem, it's handled asynchronously
			}
			// Accept failed for another reason - stop the process
			_ = processInfo.Stop()
			return nil, fmt.Errorf("failed to accept config socket connection: %w", result.err)
		}
		ctl.setConn(result.conn)
	}

	// Write initial config using gob-encoded YAML
	if err := ctl.writeConfig(confBytes); err != nil {
		_ = ctl.conn.Close()
		// Stop the process since we failed to send initial config
		_ = processInfo.Stop()
		return nil, fmt.Errorf("failed to write initial config: %w", err)
	}

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

// getCollectorHealthCheckPort returns the health check port used by the OTel collector.
// If the port set in the execution struct is 0, a random port is returned instead.
func (r *subprocessExecution) getCollectorHealthCheckPort() (int, error) {
	if r.collectorHealthCheckPort != 0 {
		return r.collectorHealthCheckPort, nil
	}
	ports, err := findRandomTCPPorts(1)
	if err != nil {
		return 0, err
	}
	return ports[0], nil
}

func addCollectorMetricsReader(conf *confmap.Conf, port int) error {
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
					"port": port,
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
	conn          net.Conn
	encoder       *gob.Encoder
}

func newProcHandle(processInfo *process.Info, log *logger.Logger, conn net.Conn) *procHandle {
	h := &procHandle{
		processDoneCh: make(chan struct{}),
		processInfo:   processInfo,
		log:           log,
		conn:          conn,
	}
	if conn != nil {
		h.encoder = gob.NewEncoder(conn)
	}
	return h
}

// setConn sets the socket connection and initializes the gob encoder.
func (s *procHandle) setConn(conn net.Conn) {
	s.conn = conn
	s.encoder = gob.NewEncoder(conn)
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

	// Close config socket connection
	if s.conn != nil {
		if closeErr := s.conn.Close(); closeErr != nil {
			s.log.Warnf("error closing otel collector config socket: %v", closeErr)
		}
	}
}

// writeConfig writes a config using gob-encoded YAML bytes.
func (s *procHandle) writeConfig(yamlBytes []byte) error {
	if err := s.encoder.Encode(yamlBytes); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// UpdateConfig sends a new configuration to the running collector via the config socket.
// Returns an error if the config could not be written.
func (s *procHandle) UpdateConfig(cfg *confmap.Conf) error {
	if cfg == nil {
		return errors.New("no configuration provided")
	}

	// Check if process is still running
	select {
	case <-s.processDoneCh:
		return errors.New("process has exited")
	default:
	}

	confMap := cfg.ToStringMap()
	yamlBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	return s.writeConfig(yamlBytes)
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
