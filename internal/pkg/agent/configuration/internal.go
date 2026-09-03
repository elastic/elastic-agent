// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"os"
	"strings"

	"github.com/elastic/elastic-agent/pkg/component"
)

// InternalKubernetesConfig controls agent-internal behaviour for Kubernetes
// integrations. It lives under agent.internal.kubernetes in the policy.
type InternalKubernetesConfig struct {
	// NativeFilelogReceiver replaces the filebeat-based kubernetes container-log
	// collection with a native OTel filelog receiver + k8sattributes processor.
	// Defaults to true. Set to false or ELASTIC_AGENT_KUBERNETES_FILELOG=false to
	// fall back to the legacy filebeat-based collection.
	NativeFilelogReceiver bool `yaml:"native_filelog_receiver" config:"native_filelog_receiver" json:"native_filelog_receiver"`
}

type InternalConfig struct {
	Runtime    *component.RuntimeConfig `yaml:"runtime" config:"runtime" json:"runtime"`
	Kubernetes InternalKubernetesConfig `yaml:"kubernetes" config:"kubernetes" json:"kubernetes"`
}

func DefaultInternalConfig() *InternalConfig {
	// ELASTIC_AGENT_KUBERNETES_FILELOG=false is an emergency escape hatch.
	// Evaluate it here (not just in container.go) so it works in every startup
	// mode, including the Helm hybrid mode that starts via `elastic-agent run`.
	nativeFilelog := true
	if v, ok := os.LookupEnv("ELASTIC_AGENT_KUBERNETES_FILELOG"); ok && strings.TrimSpace(v) != "" {
		nativeFilelog = strings.ToLower(strings.TrimSpace(v)) != "false"
	}
	return &InternalConfig{
		Runtime: component.DefaultRuntimeConfig(),
		Kubernetes: InternalKubernetesConfig{
			NativeFilelogReceiver: nativeFilelog,
		},
	}
}
