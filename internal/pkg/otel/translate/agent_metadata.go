// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import "github.com/elastic/elastic-agent/internal/pkg/agent/application/info"

// AgentMetadataProcessorID is reserved for the Agent-generated resource enrichment
// processor. Integrations opt in by referencing it in their pipelines.
const AgentMetadataProcessorID = "resource/agent_metadata"

// AgentMetadataProcessorConfig configures the stock resource processor to upsert
// Agent identity on telemetry passing through a pipeline. Integrations can copy
// these attributes into log bodies using their own transform processors.
func AgentMetadataProcessorConfig(agentInfo info.Agent) map[string]any {
	return map[string]any{
		"attributes": []any{
			map[string]any{
				"key":    "agent.id",
				"value":  agentInfo.AgentID(),
				"action": "upsert",
			},
			map[string]any{
				"key":    "agent.version",
				"value":  agentInfo.Version(),
				"action": "upsert",
			},
		},
	}
}
