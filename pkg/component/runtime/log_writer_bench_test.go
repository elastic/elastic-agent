// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/pkg/component"
)

// flatJSON is a simple log line with only scalar top-level fields.
var flatJSON = []byte(`{"@timestamp":"2009-11-10T23:00:00Z","log.level":"info","message":"batch complete","component":"exporter","records":42,"latency_ms":12}`)

// nestedJSON is a realistic OTel component log line with nested objects and arrays.
var nestedJSON = []byte(`{"@timestamp":"2009-11-10T23:00:00Z","log.level":"info","message":"spans exported","component":"exporter/otlp","resource":{"service.name":"my-service","host.name":"node-1","deployment.environment":"production"},"spans":[{"trace_id":"aabbccddeeff0011","span_id":"1122334455667788","name":"HTTP GET","attributes":{"http.method":"GET","http.url":"/api/v1/metrics","http.status_code":200,"http.response_size":1024}},{"trace_id":"aabbccddeeff0022","span_id":"2233445566778899","name":"db.query","attributes":{"db.system":"postgresql","db.statement":"SELECT id, value FROM metrics WHERE ts > $1","db.rows_affected":150,"db.duration_ms":3.7}}]}`)

type discardCore struct{}

func (d *discardCore) Write(zapcore.Entry, []zapcore.Field) error { return nil }

func newBenchWriter(ll zapcore.Level) *logWriter {
	cfg := component.CommandLogSpec{
		LevelKey:   "log.level",
		TimeKey:    "@timestamp",
		TimeFormat: time.RFC3339,
		MessageKey: "message",
	}
	return newLogWriter(&discardCore{}, cfg, ll, nil, logSourceStdout)
}

func BenchmarkHandleJSON_Flat(b *testing.B) {
	w := newBenchWriter(zapcore.InfoLevel)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.handleJSON(flatJSON)
	}
}

func BenchmarkHandleJSON_Nested(b *testing.B) {
	w := newBenchWriter(zapcore.InfoLevel)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.handleJSON(nestedJSON)
	}
}

// BenchmarkHandleJSON_Filtered benchmarks the path where the log level drops the message.
// getFields is skipped entirely in this case.
func BenchmarkHandleJSON_Filtered(b *testing.B) {
	w := newBenchWriter(zapcore.WarnLevel)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.handleJSON(nestedJSON)
	}
}
