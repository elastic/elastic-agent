// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"
	"strconv"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
)

// injectAgentTelemetryResource exposes Agent identity to collector components
// through their factory Settings.Resource, including when monitoring is disabled.
// Agent-owned attributes override configured values; other attributes are preserved.
func injectAgentTelemetryResource(cfg *confmap.Conf, agentInfo info.Agent) error {
	const resourceKey = "service::telemetry::resource"
	attributes := map[string]any{
		"elastic_agent.id":      agentInfo.AgentID(),
		"elastic_agent.version": agentInfo.Version(),
		// The legacy resource format only accepts strings or null. Use strings
		// in both formats to keep the component-facing attribute types consistent.
		"elastic_agent.snapshot": strconv.FormatBool(agentInfo.Snapshot()),
	}

	if !cfg.IsSet(resourceKey + "::attributes") {
		return cfg.Merge(confmap.NewFromStringMap(map[string]any{resourceKey: attributes}))
	}

	// The collector does not allow mixing legacy inline attributes with the
	// declarative attributes list. Preserve the format supplied by the user.
	raw := cfg.Get(resourceKey + "::attributes")
	configured, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s::attributes: expected list, got %T", resourceKey, raw)
	}
	merged := make([]any, 0, len(configured)+len(attributes))
	for _, attribute := range configured {
		if entry, ok := attribute.(map[string]any); ok {
			if name, ok := entry["name"].(string); ok {
				if _, owned := attributes[name]; owned {
					continue
				}
			}
		}
		merged = append(merged, attribute)
	}
	// Keep the generated list deterministic so identical updates do not reload
	// the collector because of a different configuration hash.
	for _, name := range []string{"elastic_agent.id", "elastic_agent.version", "elastic_agent.snapshot"} {
		merged = append(merged, map[string]any{"name": name, "value": attributes[name]})
	}
	return cfg.Merge(confmap.NewFromStringMap(map[string]any{resourceKey + "::attributes": merged}))
}
