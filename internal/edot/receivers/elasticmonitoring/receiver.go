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
	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"

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
	// Log the new metrics data so there is a record for troubleshooting in the logs / diagnostics
	mr.logger.Info("Collector internal telemetry metrics updated", zap.Reflect("metrics", resourceMetrics.ScopeMetrics))

	exporterMetrics := convertScopeMetrics(resourceMetrics.ScopeMetrics)
	for exporter, metrics := range exporterMetrics {
		componentID, ok := mr.config.ExporterNames[exporter]
		if !ok {
			mr.logger.Warn("Reporting metrics for exporter with no specified component name", zap.String("exporter_id", exporter))
			componentID = exporter
		}
		mr.sendExporterMetricsEvent(componentID, metrics)
	}

	// Send per-input metrics, one document per input, for filebeat only.
	// Metricbeat has no per-input monitoring equivalent; other beat types are
	// not expected to have a corresponding *_input datastream.
	componentMetrics := collectComponentInputMetrics(resourceMetrics.ScopeMetrics)
	for compID, compData := range componentMetrics {
		if compData.beatType != "filebeat" {
			continue
		}
		for _, inputMetrics := range compData.inputs {
			mr.sendInputMetricsEvent(compID, compData.beatType, inputMetrics)
		}
	}

	// Send per-receiver pipeline metrics, one document per Beat receiver.
	// The pipeline runs internally within each Beat receiver, so separate
	// events allow visibility into which receiver's pipeline may be backed up.
	receiverPipelineMetrics := collectReceiverMetrics(resourceMetrics.ScopeMetrics)
	for compID, fields := range receiverPipelineMetrics {
		mr.sendReceiverPipelineMetricsEvent(compID, fields)
	}
}

func (mr *monitoringReceiver) sendExporterMetricsEvent(componentID string, metrics exporterMetrics) {
	beatEvent := mapstr.M(mr.config.EventTemplate.Fields).Clone()
	addMetricsToEventFields(mr.logger, metrics, &beatEvent)
	_, _ = beatEvent.Put("component.id", componentID)
	// Any Beat running as an OTel receiver uses the otelconsumer output type by
	// definition. This is a string label, not a numeric metric, so it cannot
	// arrive via OTel internal telemetry and must be set statically here. The
	// Agent Metrics dashboard filters on this value to distinguish OTel-mode
	// output from classic Elasticsearch output.
	_, _ = beatEvent.Put("beat.stats.libbeat.output.type", "otelconsumer")
	mr.sendLogRecord(beatEvent, componentID)
}

func (mr *monitoringReceiver) sendReceiverPipelineMetricsEvent(componentID string, fields map[string]any) {
	beatEvent := mapstr.M(mr.config.EventTemplate.Fields).Clone()
	_, _ = beatEvent.Put("component.id", componentID)
	for k, v := range fields {
		_, _ = beatEvent.Put(k, v)
	}
	mr.sendLogRecord(beatEvent, componentID)
}

func (mr *monitoringReceiver) sendInputMetricsEvent(componentID string, beatType string, inputMetrics map[string]any) {
	beatEvent := mapstr.M(mr.config.InputEventTemplate.Fields).Clone()
	_, _ = beatEvent.Put("component.id", componentID)
	namespace := beatType + "_input"
	for k, v := range inputMetrics {
		_, _ = beatEvent.Put(namespace+"."+k, v)
	}
	mr.sendLogRecord(beatEvent, componentID)
}

func (mr *monitoringReceiver) sendLogRecord(beatEvent mapstr.M, componentID string) {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	sourceLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecords := sourceLogs.LogRecords()
	logRecord := logRecords.AppendEmpty()

	sourceLogs.Scope().Attributes().PutStr("elastic.mapping.mode", "bodymap")

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
		mr.logger.Error("error sending internal telemetry log record", zap.String("component.id", componentID), zap.Error(err))
	}
}
