// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"
	"slices"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
)

const (
	telemetryResourceKey = "service::telemetry::resource"
	// telemetryResourceAttributesListKey is the key of the declarative
	// attributes list inside the resource map.
	telemetryResourceAttributesListKey = "attributes"
	telemetryResourceAttributesKey     = telemetryResourceKey + "::" + telemetryResourceAttributesListKey
	telemetryDisableZapResourceKey     = "service::telemetry::logs::disable_zap_resource"
)

// telemetryResourceSchemaKeys are the keys of the declarative resource schema.
// Any other key in the resource map is an attribute in the deprecated inline
// map format.
var telemetryResourceSchemaKeys = []string{
	telemetryResourceAttributesListKey,
	"attributes_list",
	"schema_url",
	"detection/development",
}

// agentTelemetryAttribute is a collector telemetry resource attribute owned by
// Elastic Agent.
type agentTelemetryAttribute struct {
	name  string
	value any
}

// agentTelemetryAttributes returns the resource attributes owned by Elastic
// Agent. The order is fixed so identical updates produce an identical
// configuration and do not reload the collector because of a different
// configuration hash.
func agentTelemetryAttributes(agentInfo info.Agent) []agentTelemetryAttribute {
	return []agentTelemetryAttribute{
		{name: "elastic_agent.id", value: agentInfo.AgentID()},
		{name: "elastic_agent.version", value: agentInfo.Version()},
		{name: "elastic_agent.snapshot", value: agentInfo.Snapshot()},
	}
}

// injectAgentTelemetryResource exposes Agent identity to collector components
// through their factory Settings.Resource, including when monitoring is disabled.
//
// The attributes are added to the declarative service::telemetry::resource::attributes
// list, which preserves their types (snapshot is a boolean). The collector
// rejects configurations that mix that list with the deprecated inline map
// format, so when the user configured inline attributes and no list, the Agent
// attributes are added to the inline map instead. The inline format only
// accepts strings, so snapshot becomes "true" or "false" there.
//
// Agent-owned attributes override configured values; other attributes are
// preserved. Values the Agent cannot merge into, such as a ${file:...} URI in
// place of the attributes list, are left untouched with a warning instead of
// failing the whole configuration update.
//
// The attributes are also stamped on every collector log line by default. Agent
// monitoring already attaches its identity to those logs, so the duplicate is
// disabled unless the user configured service::telemetry::logs::disable_zap_resource.
func injectAgentTelemetryResource(cfg *confmap.Conf, agentInfo info.Agent, logger *logp.Logger) error {
	var resource map[string]any
	switch raw := cfg.Get(telemetryResourceKey).(type) {
	case nil:
		resource = map[string]any{}
	case map[string]any:
		resource = raw
	default:
		// Let the collector report the invalid value instead of hiding it
		// behind an Agent-generated map.
		logger.Warnf("%s is %T, not a map: agent attributes are not added to the collector telemetry resource", telemetryResourceKey, raw)
		return nil
	}

	var configured []any
	switch raw := resource[telemetryResourceAttributesListKey].(type) {
	case nil:
		// Unset or an explicit null: nothing to preserve.
	case []any:
		configured = raw
	default:
		// Most likely a ${env:...} or ${file:...} URI that the collector
		// expands after the Agent hands over the configuration.
		logger.Warnf("%s is %T, not a list: agent attributes are not added to the collector telemetry resource", telemetryResourceAttributesKey, raw)
		return nil
	}

	attributes := agentTelemetryAttributes(agentInfo)
	var injected map[string]any
	if len(configured) == 0 && hasInlineResourceAttributes(resource) {
		injected = inlineResourceAttributes(attributes)
	} else {
		injected = map[string]any{telemetryResourceAttributesListKey: declarativeResourceAttributes(configured, attributes)}
	}
	if err := cfg.Merge(confmap.NewFromStringMap(map[string]any{telemetryResourceKey: injected})); err != nil {
		return fmt.Errorf("merging agent attributes into %s: %w", telemetryResourceKey, err)
	}

	if !cfg.IsSet(telemetryDisableZapResourceKey) {
		if err := cfg.Merge(confmap.NewFromStringMap(map[string]any{telemetryDisableZapResourceKey: true})); err != nil {
			return fmt.Errorf("setting %s: %w", telemetryDisableZapResourceKey, err)
		}
	}
	return nil
}

// hasInlineResourceAttributes reports whether resource contains attributes in
// the deprecated inline map format.
func hasInlineResourceAttributes(resource map[string]any) bool {
	for key := range resource {
		if !slices.Contains(telemetryResourceSchemaKeys, key) {
			return true
		}
	}
	return false
}

// inlineResourceAttributes renders the attributes in the deprecated inline map
// format, which only accepts string or null values.
func inlineResourceAttributes(attributes []agentTelemetryAttribute) map[string]any {
	inline := make(map[string]any, len(attributes))
	for _, attribute := range attributes {
		inline[attribute.name] = fmt.Sprint(attribute.value)
	}
	return inline
}

// declarativeResourceAttributes appends the Agent attributes to the configured
// declarative attributes list, replacing configured entries with the same name.
func declarativeResourceAttributes(configured []any, attributes []agentTelemetryAttribute) []any {
	owned := make(map[string]struct{}, len(attributes))
	for _, attribute := range attributes {
		owned[attribute.name] = struct{}{}
	}
	merged := make([]any, 0, len(configured)+len(attributes))
	for _, raw := range configured {
		if entry, ok := raw.(map[string]any); ok {
			if name, ok := entry["name"].(string); ok {
				if _, isOwned := owned[name]; isOwned {
					continue
				}
			}
		}
		merged = append(merged, raw)
	}
	for _, attribute := range attributes {
		merged = append(merged, map[string]any{"name": attribute.name, "value": attribute.value})
	}
	return merged
}
