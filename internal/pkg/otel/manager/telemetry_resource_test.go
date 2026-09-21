// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
)

func TestInjectAgentTelemetryResource(t *testing.T) {
	for _, tt := range []struct {
		name     string
		resource map[string]any
	}{
		{name: "no resource configured"},
		{
			name: "legacy resource",
			resource: map[string]any{
				"custom.attribute":       "preserved",
				"elastic_agent.id":       "configured-id",
				"elastic_agent.version":  "configured-version",
				"elastic_agent.snapshot": "configured-snapshot",
				"service.name":           nil,
			},
		},
		{
			name: "declarative resource",
			resource: map[string]any{
				"schema_url": "https://example.com/schema",
				"attributes": []any{
					map[string]any{"name": "custom.attribute", "value": "preserved"},
					map[string]any{"name": "elastic_agent.id", "value": "configured-id"},
					map[string]any{"name": "elastic_agent.version", "value": "configured-version"},
					map[string]any{"name": "elastic_agent.snapshot", "value": true},
				},
			},
		},
	} {
		for _, snapshot := range []bool{false, true} {
			t.Run(tt.name+"/snapshot="+strconv.FormatBool(snapshot), func(t *testing.T) {
				agentInfo := info.NewMockAgent(t)
				agentInfo.EXPECT().AgentID().Return("test-agent-id")
				agentInfo.EXPECT().Version().Return("9.6.0")
				agentInfo.EXPECT().Snapshot().Return(snapshot)
				cfg := confmap.New()
				if tt.resource != nil {
					cfg = confmap.NewFromStringMap(map[string]any{"service::telemetry::resource": tt.resource})
				}
				require.NoError(t, injectAgentTelemetryResource(cfg, agentInfo))
				before := cfg.ToStringMap()
				require.NoError(t, injectAgentTelemetryResource(cfg, agentInfo))
				assert.Equal(t, before, cfg.ToStringMap(), "repeated injection must not change the config")

				sub, err := cfg.Sub("service::telemetry::resource")
				require.NoError(t, err)
				attrs := sub.ToStringMap()
				if tt.name == "declarative resource" {
					assert.Equal(t, "https://example.com/schema", sub.Get("schema_url"))
					assert.False(t, sub.IsSet("elastic_agent.id"), "do not mix legacy and declarative attributes")
					entries := sub.Get("attributes").([]any)
					require.Len(t, entries, 4, "Agent attributes must replace existing entries")
					attrs = make(map[string]any)
					for _, entry := range entries {
						attribute := entry.(map[string]any)
						attrs[attribute["name"].(string)] = attribute["value"]
					}
				}
				assert.Equal(t, "test-agent-id", attrs["elastic_agent.id"])
				assert.Equal(t, "9.6.0", attrs["elastic_agent.version"])
				assert.Equal(t, strconv.FormatBool(snapshot), attrs["elastic_agent.snapshot"])
				if tt.resource != nil {
					assert.Equal(t, "preserved", attrs["custom.attribute"])
				}
				if tt.name == "legacy resource" {
					assert.Contains(t, attrs, "service.name")
					assert.Nil(t, attrs["service.name"], "preserve suppression of default attributes")
				}
			})
		}
	}
}

func TestInjectAgentTelemetryResourceInvalidAttributes(t *testing.T) {
	cfg := confmap.NewFromStringMap(map[string]any{
		"service::telemetry::resource::attributes": "invalid",
	})
	err := injectAgentTelemetryResource(cfg, &info.AgentInfo{})
	require.ErrorContains(t, err, "service::telemetry::resource::attributes: expected list")
}
