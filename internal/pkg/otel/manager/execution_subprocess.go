// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"

	runtimeLogger "github.com/elastic/elastic-agent/pkg/component/runtime"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

const (
	OtelSetSupervisedFlagName                 = "supervised"
	OtelSupervisedLoggingLevelFlagName        = "supervised.logging.level"
	OtelSupervisedMonitoringURLFlagName       = "supervised.monitoring.url"
	OtelFeatureGatesFlagName                  = "feature-gates"
	OtelElasticsearchExporterTelemetryFeature = "telemetry.newPipelineTelemetry"

	// stdinGobProviderScheme must match agentprovider.StdinGobProviderSchemeName.
	// Duplicated here to avoid a cross-module import from the main module into
	// the internal/edot submodule.
	stdinGobProviderScheme = "stdingob"
)

// newSubprocessExecution creates a new execution which runs the otel collector in a subprocess.
func newSubprocessExecution(collectorPath string) (*subprocessExecution, error) {
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
		reportErrFn: reportErr,
	}, nil
}

// subprocessExecution implements collectorExecution by running the collector in a subprocess.
type subprocessExecution struct {
	collectorPath string
	collectorArgs []string
	reportErrFn   func(ctx context.Context, errCh chan error, err error) // required for testing
}

// startCollector starts a supervised collector. The collector reports its
// status to the manager's OpAMP server via the opampextension injected into
// its config; the execution layer only manages the subprocess lifecycle and
// pipes the merged config in over stdin. Process exit errors are sent to the
// processErrCh channel.
func (r *subprocessExecution) startCollector(
	_ context.Context,
	lvl logp.Level,
	collectorLogger *logger.Logger,
	logger *logger.Logger,
	cfg *confmap.Conf,
	processErrCh chan error,
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

	// prepare and serialize config first so we can exit early if there's a problem
	cfgYamlBytes, err := prepareAndSerializeConfig(cfg)
	if err != nil {
		return nil, err
	}

	stdOutLast := newZapLast(collectorLogger.Core())
	stdOut := runtimeLogger.NewLogWriterWithDefaults(stdOutLast, zapcore.Level(lvl))
	// info level for stdErr because by default collector writes to stderr
	stdErrLast := newZapLast(collectorLogger.Core())
	stdErr := runtimeLogger.NewLogWriterWithDefaults(stdErrLast, zapcore.Level(lvl))

	env := os.Environ()

	// set collector args and add --config flag with the stdingob:stdin URI
	collectorArgs := append(r.collectorArgs, fmt.Sprintf("--%s=%s", OtelSupervisedLoggingLevelFlagName, lvl))
	collectorArgs = append(collectorArgs, fmt.Sprintf("--config=%s:", stdinGobProviderScheme))

	processInfo, err := process.Start(r.collectorPath,
		process.WithArgs(collectorArgs),
		process.WithEnv(env),
		process.WithCmdOptions(func(c *exec.Cmd) error {
			c.Stdout = stdOut
			c.Stderr = stdErr
			return nil
		}),
	)
	if err != nil || processInfo.Process == nil {
		// we failed to start the process
		if err == nil {
			err = errors.New("process is nil")
		}
		return nil, fmt.Errorf("failed to start supervised collector: %w", err)
	}

	logger.Infof("supervised collector started with pid: %d", processInfo.Process.Pid)

	ctl := newProcHandle(processInfo, logger, lvl,
		func(ctx context.Context, err error) { r.reportErrFn(ctx, processErrCh, err) },
		stdOutLast, stdErrLast,
	)
	ctl.startBackgroundWorkers()
	ctl.updateConfigYamlBytes(cfgYamlBytes)
	return ctl, nil
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
					// without_scope_info=false keeps pipeline-identifying scope attributes (injected by
					// telemetry.newPipelineTelemetry) as Prometheus labels, preventing label collisions
					// when the same component type appears in multiple pipelines.
					"without_scope_info": false,
				},
			},
		},
	}
	metricsReadersList = append(metricsReadersList, metricsReader)
	confMap := map[string]any{
		"service::telemetry::metrics::readers": metricsReadersList,
	}
	if mergeErr := mergeWithExtensions(conf, confmap.NewFromStringMap(confMap)); mergeErr != nil {
		return fmt.Errorf("failed to merge config: %w", mergeErr)
	}
	return nil
}

// procHandle manages a running collector subprocess. Status reporting is
// owned by the manager's OpAMP server; this struct only deals with process
// lifecycle.
type procHandle struct {
	// processInfo holds info about the running subprocess.
	processInfo *process.Info
	// processDoneCh is closed when the subprocess exits.
	processDoneCh chan struct{}
	logger        *logger.Logger

	// wg covers all goroutines: process wait and pipe writing.
	wg sync.WaitGroup

	// reportErrFn reports a subprocess error upstream.
	reportErrFn func(ctx context.Context, err error)
	// stdOutLast captures the last stdout logger line for error reporting.
	stdOutLast *zapLast
	// stdErrLast captures the last stderr logger line for error reporting.
	stdErrLast *zapLast

	// collectorLogLevel is the logger level of the running collector.
	collectorLogLevel logp.Level
	// configCh is a buffered(1) channel for latest-config-wins config updates.
	configCh chan []byte

	// waitProcess waits for the subprocess to exit and returns its state.
	// Defaults to processInfo.Process.Wait(); overridable for testing.
	waitProcess func() (processExitState, error)
}

// processExitState is the subset of os.ProcessState that reportProcessExitErr needs.
// *os.ProcessState satisfies this interface; tests can supply a lightweight fake.
type processExitState interface {
	Success() bool
	Pid() int
	String() string
}

func newProcHandle(
	processInfo *process.Info,
	log *logger.Logger,
	collectorLogLevel logp.Level,
	reportErrFn func(ctx context.Context, err error),
	stdOutLast *zapLast,
	stdErrLast *zapLast,
) *procHandle {
	return &procHandle{
		processDoneCh:     make(chan struct{}),
		processInfo:       processInfo,
		logger:            log,
		collectorLogLevel: collectorLogLevel,
		configCh:          make(chan []byte, 1),
		reportErrFn:       reportErrFn,
		stdOutLast:        stdOutLast,
		stdErrLast:        stdErrLast,
		waitProcess: func() (processExitState, error) {
			return processInfo.Process.Wait()
		},
	}
}

func (s *procHandle) startBackgroundWorkers() {
	ctx, cancel := context.WithCancel(context.Background())
	s.startProcessMonitor(ctx, cancel)
	s.startPipeWriter(ctx)
}

func (s *procHandle) startProcessMonitor(ctx context.Context, cancel context.CancelFunc) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.monitorProcess(ctx, cancel)
	}()
}

// The pipeWriter goroutine writes the initial config and subsequent updates asynchronously to the pipe.
// Any errors are reported via reportErrFn.
func (s *procHandle) startPipeWriter(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.writeToPipe(ctx, s.processInfo.Stdin)
	}()
}

// monitorProcess waits for the subprocess to exit, then reports the exit status.
func (s *procHandle) monitorProcess(_ context.Context, cancel context.CancelFunc) {
	procState, procErr := s.waitProcess()
	s.logger.Debugf("wait for pid %d returned", s.processInfo.PID)
	cancel()
	close(s.processDoneCh)

	// the finalization process involves some operations that take a context
	// realistically, none of them can block here, but just in case
	exitCtx, exitCancel := context.WithTimeout(context.Background(), time.Second)
	defer exitCancel()

	s.reportProcessExitErr(exitCtx, procState, procErr)
}

// reportProcessExitErr reports the exit status of the collector process.
func (s *procHandle) reportProcessExitErr(ctx context.Context, procState processExitState, procErr error) {
	var allErrors []error

	// if we got an error, report it
	if procErr != nil {
		allErrors = append(allErrors, fmt.Errorf("failed to wait supervised collector process: %w", procErr))
	}

	// if the process exited with an error, get the information from logs
	if procState != nil && !procState.Success() {
		var procReportErr error
		stderrMsg := s.stdErrLast.LastMessage()
		stdoutMsg := s.stdOutLast.LastMessage()
		if stderrMsg != "" {
			// use stderr messages as the error
			procReportErr = errors.New(stderrMsg)
		} else if stdoutMsg != "" {
			// use stdout messages as the error
			procReportErr = errors.New(stdoutMsg)
		} else {
			// neither case use standard process error
			procReportErr = fmt.Errorf("supervised collector (pid: %d) exited with error: %s", procState.Pid(), procState.String())
		}
		allErrors = append(allErrors, procReportErr)
	}

	// report all the encountered errors
	s.reportErrFn(ctx, errors.Join(allErrors...))
}

// writeToPipe owns the pipe lifecycle. It loops writing configs queued via configCh until the process
// exits. Errors are reported via reportErrFn using a context tied to the process lifetime.
func (s *procHandle) writeToPipe(ctx context.Context, pipeWriter io.WriteCloser) {
	encoder := gob.NewEncoder(pipeWriter)

	// Loop: write configs until the process exits.
	for {
		select {
		case <-s.processDoneCh:
			return
		case cfgBytes := <-s.configCh:
			if err := encoder.Encode(cfgBytes); err != nil {
				// We may get an error here if we're trying to write a config, but the process exits. This isn't
				// really an error, so it's best to avoid reporting it. Check processDoneCh to be sure.
				select {
				case <-s.processDoneCh:
				default:
					if !errors.Is(err, io.ErrClosedPipe) {
						s.reportErrFn(ctx, fmt.Errorf("failed to write config update: %w", err))
					}
				}

				return
			}
		}
	}
}

// Stop stops the process. If the process is already stopped, it does nothing. If the process does not stop within
// processKillAfter or due to an error, it will be killed.
func (s *procHandle) Stop(waitTime time.Duration) {
	defer s.wg.Wait()

	select {
	case <-s.processDoneCh:
		// process has already exited
		return
	default:
	}

	s.logger.Debugf("gracefully stopping pid %d", s.processInfo.PID)
	if err := s.processInfo.Stop(); err != nil {
		s.logger.Warnf("failed to send stop signal to the supervised collector: %v", err)
		// we failed to stop the process just kill it and return
	} else {
		select {
		case <-time.After(waitTime):
			s.logger.Warnf("timeout waiting (%s) for the supervised collector to stop, killing it", waitTime.String())
		case <-s.processDoneCh:
			// process has already exited
			return
		}
	}

	// since we are here this means that the process either got an error at stop or did not stop within the timeout,
	// kill it and wait for the process to be reaped
	_ = s.processInfo.Kill()
	select {
	case <-time.After(process.KillReapTime):
		s.logger.Errorf("timed out waiting for supervised collector process %d to be reaped after SIGKILL", s.processInfo.PID)
	case <-s.processDoneCh:
		s.logger.Debugf("supervised collector process %d reaped successfully after SIGKILL", s.processInfo.PID)
	}
}

func (s *procHandle) Stopped() bool {
	select {
	case <-s.processDoneCh:
		return true
	default:
	}
	return false
}

// UpdateConfig submits a new configuration to the collector process.
func (s *procHandle) UpdateConfig(cfg *confmap.Conf) error {
	yamlBytes, err := prepareAndSerializeConfig(cfg)
	if err != nil {
		return err
	}

	s.updateConfigYamlBytes(yamlBytes)

	return nil
}

// updateConfigYamlBytes submits a new serialized configuration to the collector process.
func (s *procHandle) updateConfigYamlBytes(cfgYamlBytes []byte) {
	// Drain any pending config (latest-wins semantics).
	select {
	case <-s.configCh:
	default:
	}
	s.configCh <- cfgYamlBytes
}

// LogLevel return the otel collector's log level.
func (s *procHandle) LogLevel() logp.Level {
	return s.collectorLogLevel
}

// prepareAndSerializeConfig serializes the configuration to yaml.
func prepareAndSerializeConfig(cfg *confmap.Conf) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("no configuration provided")
	}

	confMap := cfg.ToStringMap()
	yamlBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	return yamlBytes, nil
}

type zapWriter interface {
	Write(zapcore.Entry, []zapcore.Field) error
}

// zapLast is a zapWriter that tracks the most recent error context from the
// collector subprocess. It uses a heuristic to distinguish structured (JSON)
// log entries from unstructured plain-text output:
//
//   - Structured entries (fields != nil) are normal collector logs. Each one
//     resets the accumulated messages and stands on its own.
//   - Unstructured entries (fields == nil) are plain-text lines, typically from
//     multi-line errors (e.g. errors.Join output written to stderr). These are
//     accumulated so LastMessage can reconstruct the full error.
type zapLast struct {
	wrapped zapWriter
	msgs    []string
	mx      sync.Mutex
}

func newZapLast(w zapWriter) *zapLast {
	return &zapLast{wrapped: w}
}

func (z *zapLast) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	z.mx.Lock()
	if fields != nil {
		// Structured (JSON) log entry — reset and store as standalone message.
		z.msgs = z.msgs[:0]
	}
	if entry.Message != "" {
		z.msgs = append(z.msgs, entry.Message)
	}
	z.mx.Unlock()
	return z.wrapped.Write(entry, fields)
}

// LastMessage returns the most recent message context. For multi-line
// plain-text output (e.g. errors.Join), the accumulated lines are joined
// with "; " to reconstruct the full error text.
func (z *zapLast) LastMessage() string {
	z.mx.Lock()
	defer z.mx.Unlock()
	return strings.Join(z.msgs, "; ")
}
