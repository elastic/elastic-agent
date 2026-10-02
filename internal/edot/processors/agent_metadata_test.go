// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package processors_test

import (
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
)

// Exercise the generated configuration with the actual EDOT processors. Keeping
// this test in EDOT avoids adding collector runtime dependencies to Agent.
func TestAgentMetadataProcessor(t *testing.T) {
	for _, name := range []string{"resource only", "custom bodymap transform"} {
		t.Run(name, func(t *testing.T) {
			copyToBody := name == "custom bodymap transform"
			agentInfo := info.NewMockAgent(t)
			id, version := "agent-uuid", "9.6.0"
			agentInfo.EXPECT().AgentID().Return(id)
			agentInfo.EXPECT().Version().Return(version)

			sink := &consumertest.LogsSink{}
			var next consumer.Logs = sink
			if copyToBody {
				// This transform is supplied by the integration, not by Agent.
				factory := transformprocessor.NewFactory()
				cfg := factory.CreateDefaultConfig()
				require.NoError(t, confmap.NewFromStringMap(map[string]any{
					"error_mode": "propagate",
					"log_statements": []any{map[string]any{
						"context":    "log",
						"conditions": []any{"IsMap(body)"},
						"statements": []any{
							`set(body["agent"], {}) where not IsMap(body["agent"])`,
							`set(body["agent"]["id"], resource.attributes["agent.id"])`,
							`set(body["agent"]["version"], resource.attributes["agent.version"])`,
						},
					}},
				}).Unmarshal(cfg))
				proc, err := factory.CreateLogs(t.Context(), processortest.NewNopSettings(factory.Type()), cfg, sink)
				require.NoError(t, err)
				require.NoError(t, proc.Start(t.Context(), componenttest.NewNopHost()))
				t.Cleanup(func() { require.NoError(t, proc.Shutdown(t.Context())) })
				next = proc
			}

			factory := resourceprocessor.NewFactory()
			cfg := factory.CreateDefaultConfig()
			require.NoError(t, confmap.NewFromStringMap(translate.AgentMetadataProcessorConfig(agentInfo)).Unmarshal(cfg))
			require.NoError(t, confmap.Validate(cfg))
			proc, err := factory.CreateLogs(t.Context(), processortest.NewNopSettings(factory.Type()), cfg, next)
			require.NoError(t, err)
			require.NoError(t, proc.Start(t.Context(), componenttest.NewNopHost()))
			t.Cleanup(func() { require.NoError(t, proc.Shutdown(t.Context())) })

			logs := plog.NewLogs()
			for _, attrs := range []map[string]any{
				{},
				{"agent.id": "old", "agent.version": "old"},
			} {
				rl := logs.ResourceLogs().AppendEmpty()
				require.NoError(t, rl.Resource().Attributes().FromRaw(attrs))
				rl.Resource().Attributes().PutStr("service.name", "source")
				sl := rl.ScopeLogs().AppendEmpty()
				sl.Scope().SetName("quark")
				for _, body := range []any{
					map[string]any{"message": "process started", "agent": map[string]any{"type": "quark"}},
					"plain text",
				} {
					lr := sl.LogRecords().AppendEmpty()
					lr.Attributes().PutStr("event.dataset", "quark")
					require.NoError(t, lr.Body().FromRaw(body))
				}
			}
			require.NoError(t, proc.ConsumeLogs(t.Context(), logs))
			require.Len(t, sink.AllLogs(), 1)
			out := sink.AllLogs()[0].ResourceLogs()
			require.Equal(t, 2, out.Len())
			for _, rl := range out.All() {
				assert.Equal(t, map[string]any{
					"service.name": "source", "agent.id": id, "agent.version": version,
				}, rl.Resource().Attributes().AsRaw(), "only the two Agent attributes are upserted")
				assert.Equal(t, "quark", rl.ScopeLogs().At(0).Scope().Name())
				records := rl.ScopeLogs().At(0).LogRecords()
				require.Equal(t, 2, records.Len())
				expectedAgent := map[string]any{"type": "quark"}
				if copyToBody {
					expectedAgent["id"], expectedAgent["version"] = id, version
				}
				assert.Equal(t, map[string]any{"message": "process started", "agent": expectedAgent}, records.At(0).Body().AsRaw())
				assert.Equal(t, "plain text", records.At(1).Body().AsRaw())
				for _, lr := range records.All() {
					assert.Equal(t, map[string]any{"event.dataset": "quark"}, lr.Attributes().AsRaw())
				}
			}
		})
	}
}
