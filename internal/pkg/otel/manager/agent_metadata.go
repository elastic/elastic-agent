// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"
	"slices"
	"strings"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
)

// agentMetadataProcessorID is the ID of the transform processor injected into the logs pipelines of the
// collector configuration from the policy.
const agentMetadataProcessorID = "transform/_agent-metadata"

// AgentMetadata is the Elastic Agent identity added to bodymap logs by the agent metadata processor.
type AgentMetadata struct {
	ID       string
	Version  string
	Snapshot bool
	// Name is the value of agent.name, used only when the field isn't already set. Skipped if empty.
	Name string
}

// AgentMetadataProcessorConfig returns the configuration of a transform processor setting the agent.* and
// elastic_agent.* fields on logs in the bodymap mapping mode, the same fields libbeat sets for Beats inputs.
//
// In the bodymap mapping mode the Elasticsearch exporter writes only the log body, so the fields are set in the
// body. Logs in other mapping modes aren't modified. The mapping mode is resolved the way the exporter does it: the
// elastic.mapping.mode scope attribute if set, otherwise the X-Elastic-Mapping-Mode client metadata, compared
// case-insensitively.
func AgentMetadataProcessorConfig(meta AgentMetadata) map[string]any {
	type field struct {
		path      string
		value     string // OTTL literal
		onlyIfNil bool
	}
	fields := []field{
		{path: `log.body["agent"]["id"]`, value: ottlString(meta.ID)},
		{path: `log.body["agent"]["version"]`, value: ottlString(meta.Version)},
	}
	if meta.Name != "" {
		fields = append(fields, field{path: `log.body["agent"]["name"]`, value: ottlString(meta.Name), onlyIfNil: true})
	}
	fields = append(fields,
		field{path: `log.body["agent"]["type"]`, value: ottlString("otelcol"), onlyIfNil: true},
		field{path: `log.body["elastic_agent"]["id"]`, value: ottlString(meta.ID)},
		field{path: `log.body["elastic_agent"]["version"]`, value: ottlString(meta.Version)},
		field{path: `log.body["elastic_agent"]["snapshot"]`, value: fmt.Sprintf("%t", meta.Snapshot)},
	)

	statements := make([]any, 0, len(fields))
	for _, f := range fields {
		statement := fmt.Sprintf("set(%s, %s)", f.path, f.value)
		if f.onlyIfNil {
			statement += fmt.Sprintf(" where %s == nil", f.path)
		}
		statements = append(statements, statement)
	}

	// The mapping mode check comes before IsMap on purpose: most logs aren't in bodymap mode, and IsMap formats an
	// error for every non-map body, which makes it several times more expensive than the mode check.
	// The != nil checks short-circuit so ToLowerCase never gets a nil.
	bodymapCondition := `((scope.attributes["elastic.mapping.mode"] != nil and ` +
		`ToLowerCase(scope.attributes["elastic.mapping.mode"]) == "bodymap") or ` +
		`(scope.attributes["elastic.mapping.mode"] == nil and ` +
		`otelcol.client.metadata["x-elastic-mapping-mode"] != nil and ` +
		`ToLowerCase(otelcol.client.metadata["x-elastic-mapping-mode"][0]) == "bodymap")) ` +
		`and IsMap(log.body)`

	return map[string]any{
		"error_mode": "ignore",
		"log_statements": []any{
			map[string]any{
				"context":    "log",
				"conditions": []any{bodymapCondition},
				"statements": statements,
			},
		},
	}
}

// ottlString returns s as an OTTL string literal.
func ottlString(s string) string {
	// OTTL unquotes string literals with Go escape rules.
	return fmt.Sprintf("%q", s)
}

// injectAgentMetadataProcessor returns a copy of the collector configuration with the agent metadata processor
// appended to every logs pipeline. The input configuration isn't modified. Configurations without logs pipelines
// are returned as is.
func injectAgentMetadataProcessor(cfg *confmap.Conf, agentInfo info.Agent, logger *logp.Logger) (*confmap.Conf, error) {
	if cfg == nil {
		return nil, nil
	}
	raw := cfg.ToStringMap()
	service, _ := raw["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	injected := false
	for pipelineID, pipelineCfg := range pipelines {
		if signal, _, _ := strings.Cut(pipelineID, "/"); signal != "logs" {
			continue
		}
		pipeline, ok := pipelineCfg.(map[string]any)
		if !ok {
			// Let the collector report the invalid pipeline.
			continue
		}
		var processors []any
		switch p := pipeline["processors"].(type) {
		case nil:
		case []any:
			processors = slices.Clone(p)
		case []string:
			for _, id := range p {
				processors = append(processors, id)
			}
		default:
			// Let the collector report the invalid pipeline.
			continue
		}
		if slices.Contains(processors, any(agentMetadataProcessorID)) {
			continue
		}
		// Last, so the processor sees the same scope attributes and client metadata as the exporter, and keeps
		// agent.name and agent.type set by the pipeline's own processors.
		pipeline["processors"] = append(processors, agentMetadataProcessorID)
		injected = true
	}
	if !injected {
		return cfg, nil
	}

	processorsCfg, ok := raw["processors"].(map[string]any)
	if !ok {
		if raw["processors"] != nil {
			return nil, fmt.Errorf("processors section has unexpected type %T", raw["processors"])
		}
		processorsCfg = map[string]any{}
		raw["processors"] = processorsCfg
	}
	meta := AgentMetadata{
		ID:       agentInfo.AgentID(),
		Version:  agentInfo.Version(),
		Snapshot: agentInfo.Snapshot(),
	}
	// The hostname the agent reports to Fleet, which honours ELASTIC_AGENT_HOSTNAME and the FQDN feature.
	if ecsMeta, err := agentInfo.ECSMetadata(logger); err == nil {
		meta.Name = ecsMeta.Host.Hostname
	} else {
		logger.Warnf("Failed to get the agent hostname, agent.name won't be set on bodymap logs: %v", err)
	}
	processorsCfg[agentMetadataProcessorID] = AgentMetadataProcessorConfig(meta)
	return confmap.NewFromStringMap(raw), nil
}
