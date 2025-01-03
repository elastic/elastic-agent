// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"errors"
	"time"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const hintsInputsPathPattern = "/usr/share/elastic-agent/hints.inputs.d/*.yml"

// Config for kubernetes provider
type Config struct {
	Scope     string    `config:"scope"`
	Resources Resources `config:"resources"`

	KubeConfig        string                       `config:"kube_config"`
	KubeClientOptions kubernetes.KubeClientOptions `config:"kube_client_options"`

	Namespace      string        `config:"namespace"`
	SyncPeriod     time.Duration `config:"sync_period"`
	CleanupTimeout time.Duration `config:"cleanup_timeout" validate:"positive"`

	// Needed when resource is a Pod or Node
	Node string `config:"node"`

	AddResourceMetadata *metadata.AddResourceMetadataConfig `config:"add_resource_metadata"`
	IncludeLabels       []string                            `config:"include_labels"`
	ExcludeLabels       []string                            `config:"exclude_labels"`
	IncludeAnnotations  []string                            `config:"include_annotations"`

	LabelsDedot      bool `config:"labels.dedot"`
	AnnotationsDedot bool `config:"annotations.dedot"`

	Hints  Hints  `config:"hints"`
	Prefix string `config:"prefix"`
}

// Resources config section for resources' config blocks
type Resources struct {
	Pod     Enabled `config:"pod"`
	Node    Enabled `config:"node"`
	Service Enabled `config:"service"`
}

// Hints config section for hints' config blocks
type Hints struct {
	Enabled              bool `config:"enabled"`
	DefaultContainerLogs bool `config:"default_container_logs"`
}

// Enabled config section for resources' config blocks
type Enabled struct {
	Enabled bool `config:"enabled"`
}

func GetHintsInputConfigPath(log *logger.Logger, agentCfg map[string]interface{}) string {
	hintsVal, err := utils.GetNestedMap(agentCfg, "providers", "kubernetes", "hints", "enabled")
	if err != nil {
		if errors.Is(err, utils.ErrKeyNotFound) {
			return ""
		}
		log.Errorf("error at reading providers.kubernetes.hints.enabled from config: %v", err)
		return ""
	}
	hintsEnabled, ok := hintsVal.(bool)
	if !ok || !hintsEnabled {
		return ""
	}
	return hintsInputsPathPattern
}

// InitDefaults initializes the default values for the config.
func (c *Config) InitDefaults() {
	c.CleanupTimeout = 60 * time.Second
	c.SyncPeriod = 10 * time.Minute
	c.Scope = nodeScope
	c.LabelsDedot = true
	c.AnnotationsDedot = true
	c.AddResourceMetadata = metadata.GetDefaultResourceMetadataConfig()
	c.Prefix = "co.elastic"
	c.Hints.DefaultContainerLogs = true
}

// Validate ensures correctness of config
func (c *Config) Validate() error {
	// Check if resource is service. If yes then default the scope to "cluster".
	if c.Resources.Service.Enabled {
		if c.Scope == nodeScope {
			logp.L().Warnf("can not set scope to `node` when using resource `Service`. resetting scope to `cluster`")
		}
		c.Scope = "cluster"
	}

	if !c.Resources.Pod.Enabled && !c.Resources.Node.Enabled && !c.Resources.Service.Enabled {
		c.Resources.Pod = Enabled{true}
		c.Resources.Node = Enabled{true}
	}

	return nil
}
