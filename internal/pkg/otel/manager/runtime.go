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

	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent/pkg/component/runtime"

	"go.uber.org/zap/zapcore"

	"github.com/cenkalti/backoff/v5"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

const processKillAfter = 5 * time.Second

type controller struct {
	processDoneCh chan struct{}
	processInfo   *process.Info
}

func (s *controller) Stop(ctx context.Context) {
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

// startSupervisedCollector starts a supervised collector and monitors its health. Process exit errors are sent to the
// processErrCh channel. Other run errors, such as not able to connect to the health endpoint, are sent to the runErrCh channel.
func startSupervisedCollector(ctx context.Context, logger *logger.Logger, collectorPath string, collectorArgs []string, cfg *confmap.Conf, processErrCh chan error, statusCh chan *status.AggregateStatus) (*controller, error) {
	if cfg == nil {
		// configuration is required
		return nil, errors.New("no configuration provided")
	}

	if collectorPath == "" {
		// collector path is required
		return nil, errors.New("no collector path provided")
	}

	if _, err := os.Stat(collectorPath); err != nil {
		// we cannot access the collector path
		return nil, fmt.Errorf("cannot access collector path: %w", err)
	}

	httpHealthCheckPort, err := findRandomPort()
	if err != nil {
		return nil, fmt.Errorf("could not find port for http health check: %w", err)
	}

	grpcHealthCheckPort, err := findRandomPort()
	if err != nil {
		return nil, fmt.Errorf("could not find port for grpc health check: %w", err)
	}

	if err := injectHeathCheckV2Extension(cfg, httpHealthCheckPort, grpcHealthCheckPort); err != nil {
		return nil, fmt.Errorf("failed to inject health check extension: %w", err)
	}

	confMap := cfg.ToStringMap()
	confBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	stdOut := runtime.NewLogWriterWithDefaults(logger.Core(), zapcore.InfoLevel)
	// info level for stdErr because by default collector writes to stderr
	stdErr := runtime.NewLogWriterWithDefaults(logger.Core(), zapcore.InfoLevel)

	innerCtx, innerCtxCancel := context.WithCancel(ctx)
	processInfo, err := process.Start(collectorPath,
		process.WithArgs(collectorArgs),
		process.WithContext(innerCtx),
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
		innerCtxCancel()
		return nil, fmt.Errorf("failed to start supervised collector: %w", err)
	}
	if processInfo.Process == nil {
		// this should not happen but just in case
		innerCtxCancel()
		_ = processInfo.Kill()
		return nil, fmt.Errorf("failed to start supervised collector: process is nil")
	}

	ctl := &controller{
		processDoneCh: make(chan struct{}),
		processInfo:   processInfo,
	}

	// NOTE: After this point, only the goroutine below that waits for the collector subprocess is allowed to call
	// innerCtxCancel()
	go func() {
		procState, procErr := processInfo.Process.Wait()
		innerCtxCancel()
		close(ctl.processDoneCh)
		// using ctx instead of innerCtx in the reportErr functions below is intentional. This allows us to report
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

	go func() {
		healtchCheck := func() error {
			hCheck, err := backoff.Retry(innerCtx, func() (*healthChecker, error) {
				clientConn, err := grpc.NewClient(
					fmt.Sprintf("localhost:%d", grpcHealthCheckPort),
					grpc.WithTransportCredentials(insecure.NewCredentials()),
				)
				if err != nil {
					return nil, err
				}

				client := healthpb.NewHealthClient(clientConn)
				stream, err := client.Watch(innerCtx, &healthpb.HealthCheckRequest{Service: ""})
				if err != nil {
					_ = clientConn.Close()
					return nil, err
				}
				return &healthChecker{clientConn: clientConn, stream: stream}, nil
			}, backoff.WithMaxElapsedTime(10*time.Second), backoff.WithBackOff(backoff.NewConstantBackOff(1*time.Second)))
			if err != nil {
				return err
			}

			defer func() {
				_ = hCheck.clientConn.Close()
			}()

			lastReportedStatus := healthpb.HealthCheckResponse_UNKNOWN
			for {
				resp, err := hCheck.Recv()
				if err != nil {
					return err
				}

				if resp.Status != lastReportedStatus {
					lastReportedStatus = resp.Status
					statuses, err := hCheck.AllComponentsStatuses(innerCtx, httpHealthCheckPort)
					if err != nil {
						return err
					}
					select {
					case <-innerCtx.Done():
						return innerCtx.Err()
					case statusCh <- statuses:
					}
				}
			}
		}

		for {
			if err := healtchCheck(); err != nil {
				if innerCtx.Err() != nil {
					return
				}
				reportStatus(innerCtx, statusCh, &status.AggregateStatus{
					Event: &healthCheckEvent{
						status:    componentstatus.StatusFatalError,
						timestamp: time.Now(),
						err:       err,
					},
					ComponentStatusMap: nil,
				})
				return
			}
		}
	}()

	return ctl, nil
}

func reportStatus(ctx context.Context, statusCh chan *status.AggregateStatus, statuses *status.AggregateStatus) {
	select {
	case <-ctx.Done():
		return
	case statusCh <- statuses:
	}
}
