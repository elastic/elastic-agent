// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/ecsmeta"
)

func testAgentInfo(t *testing.T) *info.MockAgent {
	agentInfo := info.NewMockAgent(t)
	agentInfo.EXPECT().AgentID().Return("test-agent-id").Maybe()
	agentInfo.EXPECT().Version().Return("9.6.0").Maybe()
	agentInfo.EXPECT().Snapshot().Return(true).Maybe()
	agentInfo.EXPECT().ECSMetadata(mock.Anything).Return(&ecsmeta.ECSMeta{
		Host: &ecsmeta.HostECSMeta{Hostname: "Test-Host", Name: "test-host"},
	}, nil).Maybe()
	return agentInfo
}

func TestInjectAgentMetadataProcessor(t *testing.T) {
	newCfg := func() *confmap.Conf {
		return confmap.NewFromStringMap(map[string]any{
			"receivers": map[string]any{"nop": map[string]any{}},
			"processors": map[string]any{
				"batch": map[string]any{},
			},
			"exporters": map[string]any{"nop": map[string]any{}},
			"service": map[string]any{
				"pipelines": map[string]any{
					"logs": map[string]any{
						"receivers": []any{"nop"},
						"exporters": []any{"nop"},
					},
					"logs/with_processors": map[string]any{
						"receivers":  []any{"nop"},
						"processors": []any{"batch"},
						"exporters":  []any{"nop"},
					},
					"metrics": map[string]any{
						"receivers":  []any{"nop"},
						"processors": []any{"batch"},
						"exporters":  []any{"nop"},
					},
					"logs/typed": map[string]any{
						"receivers":  []string{"nop"},
						"processors": []string{"batch"},
						"exporters":  []string{"nop"},
					},
					"traces/foo": map[string]any{
						"receivers": []any{"nop"},
						"exporters": []any{"nop"},
					},
				},
			},
		})
	}
	input := newCfg()

	result, err := injectAgentMetadataProcessor(input, testAgentInfo(t), logp.NewNopLogger())
	require.NoError(t, err)

	assert.Equal(t, newCfg().ToStringMap(), input.ToStringMap(), "input config must not be modified")

	assert.Equal(t, []any{agentMetadataProcessorID}, result.Get("service::pipelines::logs::processors"))
	assert.Equal(t, []any{"batch", agentMetadataProcessorID}, result.Get("service::pipelines::logs/with_processors::processors"))
	assert.Equal(t, []any{"batch", agentMetadataProcessorID}, result.Get("service::pipelines::logs/typed::processors"))
	assert.Equal(t, []any{"batch"}, result.Get("service::pipelines::metrics::processors"))
	assert.False(t, result.IsSet("service::pipelines::traces/foo::processors"))

	assert.True(t, result.IsSet("processors::batch"), "existing processors must be kept")
	expected := AgentMetadataProcessorConfig(AgentMetadata{
		ID:       "test-agent-id",
		Version:  "9.6.0",
		Snapshot: true,
		Name:     "Test-Host",
	})
	assert.Equal(t, confmap.NewFromStringMap(expected).ToStringMap(),
		result.Get("processors::"+agentMetadataProcessorID))

	t.Run("idempotent", func(t *testing.T) {
		again, err := injectAgentMetadataProcessor(result, testAgentInfo(t), logp.NewNopLogger())
		require.NoError(t, err)
		assert.Equal(t, result.ToStringMap(), again.ToStringMap())
	})
}

func TestInjectAgentMetadataProcessorNoHostname(t *testing.T) {
	agentInfo := info.NewMockAgent(t)
	agentInfo.EXPECT().AgentID().Return("test-agent-id")
	agentInfo.EXPECT().Version().Return("9.6.0")
	agentInfo.EXPECT().Snapshot().Return(false)
	agentInfo.EXPECT().ECSMetadata(mock.Anything).Return(nil, errors.New("no host info"))
	cfg := confmap.NewFromStringMap(map[string]any{
		"service": map[string]any{
			"pipelines": map[string]any{
				"logs": map[string]any{
					"receivers": []any{"nop"},
					"exporters": []any{"nop"},
				},
			},
		},
	})

	result, err := injectAgentMetadataProcessor(cfg, agentInfo, logp.NewNopLogger())
	require.NoError(t, err)
	expected := AgentMetadataProcessorConfig(AgentMetadata{ID: "test-agent-id", Version: "9.6.0"})
	assert.Equal(t, confmap.NewFromStringMap(expected).ToStringMap(), result.Get("processors::"+agentMetadataProcessorID),
		"agent.name must be skipped when the hostname is unknown")
}

func TestInjectAgentMetadataProcessorNoLogsPipelines(t *testing.T) {
	cfg := confmap.NewFromStringMap(map[string]any{
		"receivers": map[string]any{"nop": map[string]any{}},
		"exporters": map[string]any{"nop": map[string]any{}},
		"service": map[string]any{
			"pipelines": map[string]any{
				"metrics": map[string]any{
					"receivers": []any{"nop"},
					"exporters": []any{"nop"},
				},
			},
		},
	})

	result, err := injectAgentMetadataProcessor(cfg, testAgentInfo(t), logp.NewNopLogger())
	require.NoError(t, err)
	assert.Same(t, cfg, result)
	assert.False(t, result.IsSet("processors"), "processor must not be defined when no pipeline uses it")
}

func TestAgentMetadataProcessorConfig(t *testing.T) {
	cfg := AgentMetadataProcessorConfig(AgentMetadata{
		ID:      `id-with-"quotes"`,
		Version: "9.6.0",
	})
	all := strings.Join(toStrings(t, cfg), "\n")
	assert.Contains(t, all, `set(log.body["agent"]["id"], "id-with-\"quotes\"")`)
	assert.Contains(t, all, `set(log.body["elastic_agent"]["snapshot"], false)`)
	assert.NotContains(t, all, `["name"]`, "agent.name must be skipped when the name is empty")
	assert.NotContains(t, all, "resource", "only bodymap log bodies may be modified")
}

func toStrings(t *testing.T, cfg map[string]any) []string {
	t.Helper()
	var out []string
	for _, group := range cfg["log_statements"].([]any) {
		for _, s := range group.(map[string]any)["statements"].([]any) {
			out = append(out, s.(string))
		}
	}
	return out
}

// TestBuildMergedConfigAgentMetadataProcessor verifies that the agent metadata processor is added to logs pipelines
// from the collector config, but not to the pipelines of beat receivers, which set the agent metadata themselves.
func TestBuildMergedConfigAgentMetadataProcessor(t *testing.T) {
	topPath := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(topPath) })

	m := &OTelManager{
		healthCheckExtComponentID: "healthcheckv2/test",
	}
	cfgUpdate := configUpdate{
		collectorCfg: confmap.NewFromStringMap(map[string]any{
			"receivers": map[string]any{"nop": map[string]any{}},
			"exporters": map[string]any{"nop": map[string]any{}},
			"service": map[string]any{
				"pipelines": map[string]any{
					"logs/user": map[string]any{
						"receivers": []any{"nop"},
						"exporters": []any{"nop"},
					},
				},
			},
		}),
		components: []component.Component{testComponent("test-component")},
	}

	result, err := m.buildMergedConfig(cfgUpdate, &info.AgentInfo{}, logp.NewNopLogger())
	require.NoError(t, err)

	pipelines, ok := result.Get("service::pipelines").(map[string]any)
	require.True(t, ok)
	require.Greater(t, len(pipelines), 1, "expected component pipelines in the merged config")
	for id := range pipelines {
		processors := fmt.Sprint(result.Get("service::pipelines::" + id + "::processors"))
		if id == "logs/user" {
			assert.Equal(t, fmt.Sprint([]any{agentMetadataProcessorID}), processors)
		} else {
			assert.NotContains(t, processors, agentMetadataProcessorID, "pipeline %s", id)
		}
	}
	assert.True(t, result.IsSet("processors::"+agentMetadataProcessorID))
}
