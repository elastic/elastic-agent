// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package quarkreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver"

import (
	"context"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver/internal/metadata"
	"github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver/internal/sensor"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

// quarkReceiver implements receiver.Logs. It is a mock receiver that emits
// one log entry per configured interval so the OTel pipeline can be exercised
// end-to-end without requiring any external data source.
type quarkReceiver struct {
	params   receiver.Settings
	config   *Config
	consumer consumer.Logs
	logger   *zap.Logger
	queue    sensor.Queue

	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newQuarkReceiver creates a new quark receiver.
func newQuarkReceiver(
	params receiver.Settings,
	config *Config,
	consumer consumer.Logs,
) *quarkReceiver {
	return &quarkReceiver{
		params:   params,
		config:   config,
		consumer: consumer,
		logger:   params.Logger,
	}
}

// Start begins the log-emission loop in a background goroutine.
// It uses a context derived from context.Background() (not the provided ctx)
// so it is not cancelled when the Start deadline expires.
func (r *quarkReceiver) Start(_ context.Context, _ component.Host) error {
	r.logger.Info("Starting quark receiver")
	ctx, cancel := context.WithCancel(context.Background())
	r.cancelFn = cancel

	r.wg.Add(1)

	q, err := sensor.NewQueue(r.logger)
	if err != nil {
		return err
	}
	r.queue = q

	go func() {
		defer r.wg.Done()
		r.run(ctx)
	}()

	return nil
}

// Shutdown cancels the background goroutine and waits for it to exit.
func (r *quarkReceiver) Shutdown(ctx context.Context) error {
	r.logger.Info("Shutting down quark receiver")
	if r.cancelFn != nil {
		r.cancelFn()
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	if r.queue != nil {
		r.queue.Close()
	}

	select {
	case <-done:
	case <-ctx.Done():
		r.logger.Warn("Shutdown deadline exceeded; quark receiver goroutine may still be running")
	}

	return nil
}

// run ticks on the configured interval and emits one log record per tick until
// ctx is cancelled.
func (r *quarkReceiver) run(ctx context.Context) {
	ticker := time.NewTicker(r.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		event, ok := r.queue.GetEvent()
		if !ok {
			err := r.queue.Block()
			if err != nil {
				r.logger.Error("Failed to block on queue", zap.Error(err))
			}
			continue
		}

		err := r.emitLog(ctx, string(event))
		if err != nil {
			r.logger.Error("Failed to emit log", zap.Error(err))
		}
	}
}

// emitLog builds a single-record plog.Logs and forwards it to the consumer.
func (r *quarkReceiver) emitLog(ctx context.Context, msg string) error {
	now := pcommon.NewTimestampFromTime(time.Now())

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(metadata.ScopeName)
	sl.Scope().SetVersion(r.params.BuildInfo.Version)

	lr := sl.LogRecords().AppendEmpty()
	lr.SetTimestamp(now)
	lr.SetObservedTimestamp(now)
	lr.SetSeverityNumber(plog.SeverityNumberInfo)
	lr.SetSeverityText("INFO")
	lr.Body().SetStr(msg)

	return r.consumer.ConsumeLogs(ctx, logs)
}
