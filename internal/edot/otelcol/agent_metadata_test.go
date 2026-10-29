// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelcol

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"

	agentclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/otel/manager"
)

var testAgentMetadata = manager.AgentMetadata{
	AgentInfo: agentclient.AgentInfo{
		ID:       "8f3a2c1e-5b7d-4e9a-a6c2-1d4f0b9e7a35",
		Version:  "9.6.0",
		Snapshot: false,
		Tags:     []string{"tag1", "tag2"},
	},
	Hostname: "web-01",
}

// newAgentMetadataProcessor creates the transform processor with the configuration the OTel manager injects.
func newAgentMetadataProcessor(t *testing.T, next consumer.Logs) consumer.Logs {
	t.Helper()
	factory := transformprocessor.NewFactory()
	cfg := factory.CreateDefaultConfig()
	require.NoError(t, confmap.NewFromStringMap(manager.AgentMetadataProcessorConfig(testAgentMetadata)).Unmarshal(cfg))
	p, err := factory.CreateLogs(t.Context(), processortest.NewNopSettings(factory.Type()), cfg, next)
	require.NoError(t, err)
	require.NoError(t, p.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		// t.Context() is already cancelled when cleanup runs.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, p.Shutdown(ctx))
	})
	return p
}

type agentMetadataTestCase struct {
	name string
	// scopeMode is the elastic.mapping.mode scope attribute, unset if empty.
	scopeMode string
	// requestMode is the X-Elastic-Mapping-Mode client metadata, unset if empty.
	requestMode string
	mapBody     bool
	// bodymap is whether the Elasticsearch exporter would use the bodymap mapping mode.
	bodymap bool
}

var agentMetadataTestCases = []agentMetadataTestCase{
	{name: "otel string body"},
	{name: "otel map body", mapBody: true},
	{name: "otel scope attribute", scopeMode: "otel", mapBody: true},
	{name: "bodymap scope attribute", scopeMode: "bodymap", mapBody: true, bodymap: true},
	{name: "bodymap scope attribute mixed case", scopeMode: "BodyMap", mapBody: true, bodymap: true},
	{name: "bodymap request metadata", requestMode: "bodymap", mapBody: true, bodymap: true},
	{name: "scope attribute overrides request metadata", scopeMode: "otel", requestMode: "bodymap", mapBody: true},
	{name: "bodymap string body", scopeMode: "bodymap", bodymap: true},
}

// context returns ctx with the test case's request metadata.
func (tc agentMetadataTestCase) context(ctx context.Context) context.Context {
	if tc.requestMode != "" {
		ctx = client.NewContext(ctx, client.Info{
			Metadata: client.NewMetadata(map[string][]string{"X-Elastic-Mapping-Mode": {tc.requestMode}}),
		})
	}
	return ctx
}

// logs returns one resource and one scope with n log records. Map bodies are shaped like a small ECS document.
func (tc agentMetadataTestCase) logs(n int) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("host.name", "web-01")
	sl := rl.ScopeLogs().AppendEmpty()
	if tc.scopeMode != "" {
		sl.Scope().Attributes().PutStr("elastic.mapping.mode", tc.scopeMode)
	}
	for i := range n {
		lr := sl.LogRecords().AppendEmpty()
		if !tc.mapBody {
			lr.Body().SetStr(fmt.Sprintf("GET /index.html 200 %d", i))
			continue
		}
		body := lr.Body().SetEmptyMap()
		body.PutStr("@timestamp", "2026-10-21T10:00:00Z")
		body.PutStr("message", fmt.Sprintf("GET /index.html 200 %d", i))
		event := body.PutEmptyMap("event")
		event.PutStr("kind", "event")
		event.PutStr("category", "network")
		event.PutStr("dataset", "akamai.siem")
		dataStream := body.PutEmptyMap("data_stream")
		dataStream.PutStr("type", "logs")
		dataStream.PutStr("dataset", "akamai.siem")
		dataStream.PutStr("namespace", "default")
		source := body.PutEmptyMap("source")
		source.PutStr("ip", "10.0.0.1")
		source.PutInt("port", 51234)
		http := body.PutEmptyMap("http")
		http.PutEmptyMap("request").PutStr("method", "GET")
		http.PutEmptyMap("response").PutInt("status_code", 200)
		url := body.PutEmptyMap("url")
		url.PutStr("path", "/index.html")
		url.PutStr("domain", "example.com")
		body.PutEmptyMap("host").PutStr("name", "web-01")
	}
	return ld
}

func TestAgentMetadataProcessor(t *testing.T) {
	for _, tc := range agentMetadataTestCases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &consumertest.LogsSink{}
			p := newAgentMetadataProcessor(t, sink)

			input := tc.logs(3)
			// Sections that already exist are kept as they are. Tags are only added with the elastic_agent section.
			if tc.mapBody {
				records := input.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
				records.At(0).Body().Map().PutEmptyMap("agent").PutStr("id", "other-agent-id")
				second := records.At(1).Body().Map()
				second.PutEmptyMap("elastic_agent").PutStr("id", "other-agent-id")
				second.PutEmptySlice("tags").AppendEmpty().SetStr("existing")
				records.At(2).Body().Map().PutEmptySlice("tags").AppendEmpty().SetStr("existing")
			}

			// Only the bodies of bodymap logs may change.
			expected := plog.NewLogs()
			input.CopyTo(expected)
			if tc.bodymap && tc.mapBody {
				records := expected.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
				for i := range records.Len() {
					body := records.At(i).Body().Map()
					if _, ok := body.Get("agent"); !ok {
						agent := body.PutEmptyMap("agent")
						agent.PutStr("id", testAgentMetadata.ID)
						agent.PutStr("version", testAgentMetadata.Version)
						agent.PutStr("name", testAgentMetadata.Hostname)
						agent.PutStr("type", "otelcol")
					}
					if _, ok := body.Get("elastic_agent"); !ok {
						var tags pcommon.Slice
						if existing, ok := body.Get("tags"); ok {
							tags = existing.Slice()
						} else {
							tags = body.PutEmptySlice("tags")
						}
						for _, tag := range testAgentMetadata.Tags {
							tags.AppendEmpty().SetStr(tag)
						}
						elasticAgent := body.PutEmptyMap("elastic_agent")
						elasticAgent.PutStr("id", testAgentMetadata.ID)
						elasticAgent.PutStr("version", testAgentMetadata.Version)
						elasticAgent.PutBool("snapshot", testAgentMetadata.Snapshot)
					}
				}
			}

			require.NoError(t, p.ConsumeLogs(tc.context(t.Context()), input))

			require.Len(t, sink.AllLogs(), 1)
			actual := sink.AllLogs()[0]
			// Bodies are compared as raw values, since the order of map entries doesn't matter, then cleared so the
			// rest of the logs can be compared as a whole.
			expectedRecords := expected.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
			actualRecords := actual.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
			require.Equal(t, expectedRecords.Len(), actualRecords.Len())
			for i := range expectedRecords.Len() {
				assert.Equal(t, expectedRecords.At(i).Body().AsRaw(), actualRecords.At(i).Body().AsRaw(), "body of record %d", i)
				expectedRecords.At(i).Body().SetStr("")
				actualRecords.At(i).Body().SetStr("")
			}
			assert.JSONEq(t, logsJSON(t, expected), logsJSON(t, actual), "only log bodies may be modified")
		})
	}
}

func logsJSON(t *testing.T, ld plog.Logs) string {
	t.Helper()
	b, err := (&plog.JSONMarshaler{}).MarshalLogs(ld)
	require.NoError(t, err)
	return string(b)
}
