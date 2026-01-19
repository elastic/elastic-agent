// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/elastic/beats/v7/x-pack/otel/otelmap"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/otel/internaltelemetry"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
)

type monitoringReceiver struct {
	logger   *zap.Logger
	config   *Config
	consumer consumer.Logs

	runCtx context.Context
	cancel context.CancelFunc

	// done is closed to signal that the receiver is finished shutting down.
	// We use a channel rather than a wait group so the wait duration can
	// be controlled by a provided context.
	done chan struct{}
}

func createReceiver(
	ctx context.Context,
	set receiver.Settings,
	baseCfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	cfg := baseCfg.(*Config)

	runCtx, cancel := context.WithCancel(context.Background())

	return &monitoringReceiver{
		logger:   set.Logger,
		config:   cfg,
		consumer: consumer,
		runCtx:   runCtx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}, nil
}

func (mr *monitoringReceiver) Start(ctx context.Context, _ component.Host) error {
	go func() {
		defer close(mr.done)
		mr.run()
	}()
	return nil
}

func (mr *monitoringReceiver) Shutdown(ctx context.Context) error {
	mr.cancel()
	// Wait for the run loop to stop, but return immediately if the context
	// is cancelled.
	select {
	case <-mr.done:
	case <-ctx.Done():
	}
	return nil
}

func (mr *monitoringReceiver) run() {
	mr.updateMetrics()
	for mr.runCtx.Err() == nil {
		select {
		case <-mr.runCtx.Done():
		case <-time.After(mr.config.Interval):
			mr.updateMetrics()
		}
	}
}

func (mr *monitoringReceiver) updateMetrics() {
	resourceMetrics, err := internaltelemetry.ReadMetrics(mr.runCtx)
	if err != nil {
		// This isn't inherently an error state, internal telemetry could
		// be manually disabled, but it's not the expected path.
		mr.logger.Info("couldn't collect metrics", zap.Error(err))
		return
	}

	exporterMetrics := convertScopeMetrics(resourceMetrics.ScopeMetrics)
	for exporter, metrics := range exporterMetrics {
		mr.sendExporterMetricsEvent(exporter, metrics)
	}
}

func (mr *monitoringReceiver) sendExporterMetricsEvent(exporter string, metrics exporterMetrics) {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	sourceLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecords := sourceLogs.LogRecords()
	logRecord := logRecords.AppendEmpty()

	// Initialize to the configured event template
	beatEvent := mapstr.M(mr.config.EventTemplate.Fields).Clone()
	addMetricsToEventFields(mr.logger, metrics, &beatEvent)
	_, _ = beatEvent.Put("component.id", exporter)

	// Set timestamp
	now := time.Now()
	beatEvent["@timestamp"] = now
	timestamp := pcommon.NewTimestampFromTime(now)
	logRecord.SetTimestamp(timestamp)
	logRecord.SetObservedTimestamp(timestamp)

	// Convert fields to OTel-primitive types, if needed
	otelmap.ConvertNonPrimitive(beatEvent)

	// Add data_stream metadata to the log record attributes
	if val, _ := beatEvent.GetValue("data_stream"); val != nil {
		for _, subField := range []string{"dataset", "namespace", "type"} {
			value, err := beatEvent.GetValue("data_stream." + subField)
			if vStr, ok := value.(string); ok && err == nil {
				// set log record attribute only if value is non empty
				logRecord.Attributes().PutStr("data_stream."+subField, vStr)
			}
		}

	}

	// Set log record body to computed fields
	if err := logRecord.Body().SetEmptyMap().FromRaw(map[string]any(beatEvent)); err != nil {
		mr.logger.Error("couldn't convert map to plog.Log, some fields might be missing", zap.Error(err))
	}

	err := mr.consumer.ConsumeLogs(mr.runCtx, pLogs)
	if err != nil && mr.runCtx.Err() == nil {
		// Don't log an error if the context is cancelled, that's just a normal shutdown
		mr.logger.Error("error sending internal telemetry log record", zap.String("exporter", exporter), zap.Error(err))
	}
}
