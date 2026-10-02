// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/featuregate"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
)

const (
	testAgentID      = "test-agent-id"
	testAgentVersion = "9.6.0"
)

// testAgent is agent info with known, non-empty values for the attributes
// exposed through the collector telemetry resource.
type testAgent struct {
	*info.AgentInfo
	snapshot bool
}

func (testAgent) AgentID() string { return testAgentID }

func (testAgent) Version() string { return testAgentVersion }

func (a testAgent) Snapshot() bool { return a.snapshot }

func newTestAgentInfo(snapshot bool) info.Agent {
	return testAgent{AgentInfo: &info.AgentInfo{}, snapshot: snapshot}
}

// declarativeResourceAttributesOf returns the service::telemetry::resource::attributes
// list of cfg as a name to value map.
func declarativeResourceAttributesOf(t *testing.T, cfg *confmap.Conf) map[string]any {
	t.Helper()
	entries, ok := cfg.Get(telemetryResourceAttributesKey).([]any)
	require.True(t, ok, "expected a declarative attributes list, got %T", cfg.Get(telemetryResourceAttributesKey))
	attrs := make(map[string]any, len(entries))
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		require.True(t, ok, "attribute entry must be a map, got %T", raw)
		name, ok := entry["name"].(string)
		require.True(t, ok, "attribute entry must have a string name: %v", entry)
		attrs[name] = entry["value"]
	}
	return attrs
}

// inlineResourceAttributesOf returns the deprecated inline attributes of
// service::telemetry::resource in cfg.
func inlineResourceAttributesOf(t *testing.T, cfg *confmap.Conf) map[string]any {
	t.Helper()
	resource, ok := cfg.Get(telemetryResourceKey).(map[string]any)
	require.True(t, ok, "expected a resource map, got %T", cfg.Get(telemetryResourceKey))
	for _, key := range telemetryResourceSchemaKeys {
		delete(resource, key)
	}
	return resource
}

// requireValidCollectorResource applies the rules of ResourceConfig.Validate in
// go.opentelemetry.io/collector/service/telemetry/otelconftelemetry to the
// injected resource, so the test fails when the Agent produces a configuration
// the collector would reject. The rules are replicated because importing that
// package pulls resource detectors and other heavy dependencies into this module.
func requireValidCollectorResource(t *testing.T, cfg *confmap.Conf) {
	t.Helper()
	resource, ok := cfg.Get(telemetryResourceKey).(map[string]any)
	require.True(t, ok, "expected a resource map, got %T", cfg.Get(telemetryResourceKey))
	require.NotContains(t, resource, "attributes_list", "resource::attributes_list is not supported by the collector")

	list, _ := resource[telemetryResourceAttributesListKey].([]any)
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		require.True(t, ok, "attribute entry must be a map, got %T", raw)
		_, ok = entry["name"].(string)
		require.True(t, ok, "attribute entry must have a string name: %v", entry)
		require.NotNil(t, entry["value"], "attribute entry must have a value: %v", entry)
	}

	inline := inlineResourceAttributesOf(t, cfg)
	for key, value := range inline {
		switch value.(type) {
		case nil, string:
		default:
			t.Fatalf("inline resource attribute %q must be string or null, got %T", key, value)
		}
	}
	if len(list) > 0 {
		require.Empty(t, inline, "resource::attributes cannot be used together with inline resource attributes")
	}
}

// setMergeAppendFeatureGate sets the confmap feature gate the Agent enables in
// production (see cmd/run.go) and restores the previous state on cleanup.
func setMergeAppendFeatureGate(t *testing.T, enabled bool) {
	t.Helper()
	const id = "confmap.enableMergeAppendOption"
	registry := featuregate.GlobalRegistry()
	var previous bool
	registry.VisitAll(func(gate *featuregate.Gate) {
		if gate.ID() == id {
			previous = gate.IsEnabled()
		}
	})
	require.NoError(t, registry.Set(id, enabled))
	t.Cleanup(func() { require.NoError(t, registry.Set(id, previous)) })
}

func TestInjectAgentTelemetryResource(t *testing.T) {
	tests := []struct {
		name string
		// cfg is the collector configuration before injection, in confmap key notation.
		cfg map[string]any
		// wantUnchanged expects the injection to be a no-op.
		wantUnchanged bool
		// wantInline expects the Agent attributes as strings in the deprecated
		// inline map instead of the declarative attributes list.
		wantInline bool
		// check holds case specific assertions on the injected configuration.
		check func(t *testing.T, cfg *confmap.Conf)
	}{
		{
			name: "no resource configured",
			check: func(t *testing.T, cfg *confmap.Conf) {
				assert.Len(t, declarativeResourceAttributesOf(t, cfg), 3)
			},
		},
		{
			name: "resource is null",
			cfg:  map[string]any{telemetryResourceKey: nil},
			check: func(t *testing.T, cfg *confmap.Conf) {
				assert.Len(t, declarativeResourceAttributesOf(t, cfg), 3)
			},
		},
		{
			name: "attributes is null",
			cfg:  map[string]any{telemetryResourceAttributesKey: nil},
			check: func(t *testing.T, cfg *confmap.Conf) {
				assert.Len(t, declarativeResourceAttributesOf(t, cfg), 3)
			},
		},
		{
			name: "attributes is an empty list",
			cfg:  map[string]any{telemetryResourceAttributesKey: []any{}},
			check: func(t *testing.T, cfg *confmap.Conf) {
				assert.Len(t, declarativeResourceAttributesOf(t, cfg), 3)
			},
		},
		{
			name: "declarative resource",
			cfg: map[string]any{
				telemetryResourceKey: map[string]any{
					"schema_url": "https://example.com/schema",
					"attributes": []any{
						map[string]any{"name": "custom.attribute", "value": "preserved"},
						map[string]any{"name": "elastic_agent.id", "value": "configured-id"},
						map[string]any{"name": "elastic_agent.version", "value": "configured-version"},
						map[string]any{"name": "elastic_agent.snapshot", "value": "configured-snapshot"},
					},
				},
			},
			check: func(t *testing.T, cfg *confmap.Conf) {
				attrs := declarativeResourceAttributesOf(t, cfg)
				assert.Len(t, attrs, 4, "Agent attributes must replace configured entries with the same name")
				assert.Equal(t, "preserved", attrs["custom.attribute"])
				assert.Equal(t, "https://example.com/schema", cfg.Get(telemetryResourceKey+"::schema_url"))
				assert.Empty(t, inlineResourceAttributesOf(t, cfg), "must not mix inline and declarative attributes")
			},
		},
		{
			name: "inline resource",
			cfg: map[string]any{
				telemetryResourceKey: map[string]any{
					"custom.attribute":       "preserved",
					"elastic_agent.id":       "configured-id",
					"elastic_agent.version":  "configured-version",
					"elastic_agent.snapshot": "configured-snapshot",
					"service.name":           nil,
				},
			},
			wantInline: true,
			check: func(t *testing.T, cfg *confmap.Conf) {
				attrs := inlineResourceAttributesOf(t, cfg)
				assert.Equal(t, "preserved", attrs["custom.attribute"])
				assert.Contains(t, attrs, "service.name")
				assert.Nil(t, attrs["service.name"], "preserve suppression of default attributes")
				assert.False(t, cfg.IsSet(telemetryResourceAttributesKey), "must not mix inline and declarative attributes")
			},
		},
		{
			name: "empty list with inline attributes",
			cfg: map[string]any{
				telemetryResourceKey: map[string]any{
					"attributes":   []any{},
					"service.name": "custom-service",
				},
			},
			wantInline: true,
			check: func(t *testing.T, cfg *confmap.Conf) {
				assert.Equal(t, "custom-service", inlineResourceAttributesOf(t, cfg)["service.name"])
				assert.Empty(t, cfg.Get(telemetryResourceAttributesKey), "must not mix inline and declarative attributes")
			},
		},
		{
			name:          "attributes is a URI expanded by the collector",
			cfg:           map[string]any{telemetryResourceAttributesKey: "${file:/etc/otel/resource.yaml}"},
			wantUnchanged: true,
		},
		{
			name:          "resource is not a map",
			cfg:           map[string]any{telemetryResourceKey: "bogus"},
			wantUnchanged: true,
		},
		{
			name: "user configured zap resource logging",
			cfg:  map[string]any{telemetryDisableZapResourceKey: false},
			check: func(t *testing.T, cfg *confmap.Conf) {
				assert.Equal(t, false, cfg.Get(telemetryDisableZapResourceKey), "user setting must be preserved")
			},
		},
	}

	// The Agent enables the confmap merge-append feature gate in production.
	// The attributes list must be replaced, not appended to, in both modes.
	for _, mergeAppend := range []bool{false, true} {
		t.Run(fmt.Sprintf("mergeAppend=%t", mergeAppend), func(t *testing.T) {
			setMergeAppendFeatureGate(t, mergeAppend)
			for _, snapshot := range []bool{false, true} {
				for _, tt := range tests {
					t.Run(fmt.Sprintf("%s/snapshot=%t", tt.name, snapshot), func(t *testing.T) {
						agentInfo := newTestAgentInfo(snapshot)
						cfg := confmap.NewFromStringMap(tt.cfg)
						initial := cfg.ToStringMap()

						require.NoError(t, injectAgentTelemetryResource(cfg, agentInfo, logp.NewNopLogger()))
						injected := cfg.ToStringMap()
						require.NoError(t, injectAgentTelemetryResource(cfg, agentInfo, logp.NewNopLogger()))
						assert.Equal(t, injected, cfg.ToStringMap(), "repeated injection must not change the config")

						if tt.wantUnchanged {
							assert.Equal(t, initial, injected, "configuration must be left untouched")
							return
						}

						requireValidCollectorResource(t, cfg)
						if tt.cfg[telemetryDisableZapResourceKey] == nil {
							assert.Equal(t, true, cfg.Get(telemetryDisableZapResourceKey), "zap resource logging must be disabled by default")
						}

						if tt.wantInline {
							attrs := inlineResourceAttributesOf(t, cfg)
							assert.Equal(t, testAgentID, attrs["elastic_agent.id"])
							assert.Equal(t, testAgentVersion, attrs["elastic_agent.version"])
							assert.Equal(t, fmt.Sprint(snapshot), attrs["elastic_agent.snapshot"], "inline format only accepts strings")
						} else {
							attrs := declarativeResourceAttributesOf(t, cfg)
							assert.Equal(t, testAgentID, attrs["elastic_agent.id"])
							assert.Equal(t, testAgentVersion, attrs["elastic_agent.version"])
							assert.Equal(t, snapshot, attrs["elastic_agent.snapshot"], "declarative format keeps the boolean type")
						}
						if tt.check != nil {
							tt.check(t, cfg)
						}
					})
				}
			}
		})
	}
}
