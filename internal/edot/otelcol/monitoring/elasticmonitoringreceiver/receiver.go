// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringreceiver

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/beats/v7/libbeat/otelbeat/otelmap"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/edot/otelcol/monitoring/internaltelemetry"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	Name = "elasticmonitoringreceiver"
)

type Config struct {
	EventTemplate struct {
		Fields map[string]interface{} `mapstructure:",remain"`
	} `mapstructure:"event_template"`
}

type monitoringReceiver struct {
	config   *Config
	host     component.Host
	consumer consumer.Logs
}

func (mr *monitoringReceiver) Start(ctx context.Context, host component.Host) error {
	mr.host = host
	go mr.run(ctx)
	return nil
	//return errors.New("hi fae")
}

func (mr *monitoringReceiver) Shutdown(ctx context.Context) error {

	return nil
}

func (mr *monitoringReceiver) run(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
			mr.updateMetrics(ctx)
		}

	}
}

func addMetricsFields(ctx context.Context, event *mapstr.M) {
	metrics, err := internaltelemetry.ReadMetrics(ctx)
	if err != nil {
		return
	}
	var exporter_queue_size *int64
	for _, scope := range metrics.ScopeMetrics {
		for _, met := range scope.Metrics {
			if met.Name == "otelcol_exporter_queue_size" {
				if d, ok := met.Data.(metricdata.Gauge[int64]); ok { //met.Data.(metricdata.Sum[int64]); ok {
					var total int64
					for _, dp := range d.DataPoints {
						total += dp.Value
					}
					exporter_queue_size = &total
				}
			}

		}
	}

	if exporter_queue_size != nil {
		event.Put("beat.stats.libbeat.pipeline.queue.filled.events", *exporter_queue_size)
		fmt.Printf("HI FAE HI FAE HI FAE I JUST ADDED AN EXPORTER QUEUE SIZE")
	}
}

func (mr *monitoringReceiver) updateMetrics(ctx context.Context) {

	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	sourceLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecords := sourceLogs.LogRecords()
	logRecord := logRecords.AppendEmpty()

	//beatEvent := mr.eventFields() //mapstr.M{}
	beatEvent := mapstr.M(mr.config.EventTemplate.Fields).Clone()

	addMetricsFields(ctx, &beatEvent)

	now := time.Now()
	timestamp := pcommon.NewTimestampFromTime(now)
	beatEvent["@timestamp"] = now

	logRecord.SetTimestamp(timestamp)
	logRecord.SetObservedTimestamp(timestamp)
	otelmap.ConvertNonPrimitive(beatEvent)

	if val, _ := beatEvent.GetValue("data_stream"); val != nil {
		// If the below sub fields do not exist, it will return empty string.
		subFields := []string{"dataset", "namespace", "type"}

		for _, subField := range subFields {
			// value, ok := data.Map().Get(subField)
			value, err := beatEvent.GetValue("data_stream." + subField)
			if vStr, ok := value.(string); ok && err == nil {
				// set log record attribute only if value is non empty
				logRecord.Attributes().PutStr("data_stream."+subField, vStr)
			}
		}

	}

	if err := logRecord.Body().SetEmptyMap().FromRaw(map[string]any(beatEvent)); err != nil {
		//out.log.Errorf("received an error while converting map to plog.Log, some fields might be missing: %v", err)
	}

	mr.consumer.ConsumeLogs(ctx, pLogs)
}

func (mr *monitoringReceiver) eventFields() mapstr.M {
	// beat.stats.libbeat.pipeline.queue.filled.pct
	m := mapstr.M{
		"data_stream": mapstr.M{
			"dataset":   "elastic_agent.elastic_agent",
			"namespace": "default",
			"type":      "metrics",
		},
		"event": mapstr.M{
			"dataset": "elastic_agent.elastic_agent",
		},
		"elastic_agent": mapstr.M{
			"id":       "70c129a6-0075-47f4-9777-b88577afa393",
			"process":  "elastic-agent",
			"snapshot": false,
			"version":  "9.3.0",
		},
		"agent": mapstr.M{
			"id": "70c129a6-0075-47f4-9777-b88577afa393",
		},
		"component": mapstr.M{
			"binary": "elastic-agent",
			"id":     "elastic-agent/collector",
		},
		"metricset": mapstr.M{
			"name": "stats",
		},
	}
	m.Put("beat.stats.libbeat.pipeline.queue.filled.pct", 0.5)
	return m
}

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(Name),
		createDefaultConfig,
		receiver.WithLogs(createReceiver, component.StabilityLevelAlpha))
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createReceiver(
	ctx context.Context,
	set receiver.Settings,
	baseCfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	cfg := baseCfg.(*Config)

	return &monitoringReceiver{
		config:   cfg,
		consumer: consumer,
	}, nil
}
