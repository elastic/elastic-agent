// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
)

func TestInjectAgentMetadataProcessor(t *testing.T) {
	for _, processors := range [][]any{{"batch"}, {"batch", translate.AgentMetadataProcessorID}} {
		t.Run(processors[len(processors)-1].(string), func(t *testing.T) {
			cfg := confmap.NewFromStringMap(map[string]any{
				"processors::batch":                          map[string]any{"timeout": "1s"},
				"service::pipelines::logs::processors":       processors,
				"service::telemetry::resource::service.name": "custom-collector",
			})
			original := cfg.ToStringMap()
			require.NoError(t, injectAgentMetadataProcessor(cfg, &info.AgentInfo{}))
			assert.True(t, cfg.IsSet("processors::"+translate.AgentMetadataProcessorID))
			assert.Equal(t, processors, cfg.Get("service::pipelines::logs::processors"), "pipeline membership and ordering are opt-in")
			actual := cfg.ToStringMap()
			delete(actual["processors"].(map[string]any), translate.AgentMetadataProcessorID)
			assert.Equal(t, original, actual, "only the processor definition should change")
		})
	}
}

func TestInjectAgentMetadataProcessorReservedName(t *testing.T) {
	for _, value := range []any{nil, map[string]any{}, map[string]any{"attributes": []any{map[string]any{"key": "custom", "action": "delete"}}}} {
		cfg := confmap.NewFromStringMap(map[string]any{"processors::" + translate.AgentMetadataProcessorID: value})
		original := cfg.ToStringMap()
		err := injectAgentMetadataProcessor(cfg, &info.AgentInfo{})
		require.ErrorContains(t, err, "reserved for Elastic Agent")
		assert.Equal(t, original, cfg.ToStringMap())
	}
}
