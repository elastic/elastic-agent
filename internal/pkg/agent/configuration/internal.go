// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"os"
	"strings"

	"github.com/elastic/elastic-agent/pkg/component"
)

// containerLogsGlobInputEnvVar is the emergency escape hatch for the glob input
// rewrite. Setting it to "false" restores the per-container dynamic inputs.
const containerLogsGlobInputEnvVar = "ELASTIC_AGENT_KUBERNETES_CONTAINER_LOGS_GLOB"

// InternalKubernetesConfig controls agent-internal behaviour for Kubernetes
// integrations. It lives under agent.internal.kubernetes in the policy.
type InternalKubernetesConfig struct {
	// ContainerLogsGlobInput collapses the per-container kubernetes.container_logs
	// filestream inputs produced by the kubernetes dynamic provider into a single
	// static filestream watching a glob path, with an add_kubernetes_metadata
	// processor supplying the Kubernetes metadata.
	//
	// Defaults to true. Set to false, or ELASTIC_AGENT_KUBERNETES_CONTAINER_LOGS_GLOB=false,
	// to fall back to one filestream input per discovered container.
	ContainerLogsGlobInput bool `yaml:"container_logs_glob_input" config:"container_logs_glob_input" json:"container_logs_glob_input"`
}

type InternalConfig struct {
	Runtime    *component.RuntimeConfig `yaml:"runtime" config:"runtime" json:"runtime"`
	Kubernetes InternalKubernetesConfig `yaml:"kubernetes" config:"kubernetes" json:"kubernetes"`
}

func DefaultInternalConfig() *InternalConfig {
	// Evaluate the escape hatch here (not just in container.go) so it works in
	// every startup mode, including the Helm hybrid mode that starts via
	// `elastic-agent run`.
	globInput := true
	if v, ok := os.LookupEnv(containerLogsGlobInputEnvVar); ok && strings.TrimSpace(v) != "" {
		globInput = !strings.EqualFold(strings.TrimSpace(v), "false")
	}
	return &InternalConfig{
		Runtime: component.DefaultRuntimeConfig(),
		Kubernetes: InternalKubernetesConfig{
			ContainerLogsGlobInput: globInput,
		},
	}
}
