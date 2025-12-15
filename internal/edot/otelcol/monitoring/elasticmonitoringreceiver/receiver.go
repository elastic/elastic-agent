// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringreceiver

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/elastic/beats/v7/libbeat/otelbeat/otelmap"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

type monitoringReceiver struct {
	config   *Config
	consumer consumer.Logs

	ctx    context.Context
	cancel context.CancelFunc
	host   component.Host
	wg     sync.WaitGroup
}

func (mr *monitoringReceiver) Start(ctx context.Context, host component.Host) error {
	mr.ctx, mr.cancel = context.WithCancel(ctx)
	mr.host = host
	mr.wg.Add(1)
	go func() {
		defer mr.wg.Done()
		mr.run()
	}()
	return nil
}

func (mr *monitoringReceiver) Shutdown(ctx context.Context) error {
	mr.cancel()
	mr.wg.Wait()
	return nil
}

func (mr *monitoringReceiver) run() {
	for mr.ctx.Err() == nil {
		select {
		case <-mr.ctx.Done():
		case <-time.After(mr.config.interval):
			mr.updateMetrics()
		}
	}
}

func (mr *monitoringReceiver) updateMetrics() {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	sourceLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecords := sourceLogs.LogRecords()
	logRecord := logRecords.AppendEmpty()

	// Initialize to the configured event template
	beatEvent := mapstr.M(mr.config.EventTemplate.Fields).Clone()

	// Add internal telemetry data
	addMetricsFields(mr.ctx, &beatEvent)

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
		//out.log.Errorf("received an error while converting map to plog.Log, some fields might be missing: %v", err)
	}

	mr.consumer.ConsumeLogs(mr.ctx, pLogs)
}
