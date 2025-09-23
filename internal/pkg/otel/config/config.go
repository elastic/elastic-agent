// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/otel/manager"
)

var executionMode = manager.EmbeddedExecutionMode

type execModeConfig struct {
	Agent struct {
		Features struct {
			Otel *struct {
				SubprocessExecution bool `json:"subprocess_execution" yaml:"subprocess_execution" config:"subprocess_execution"`
			} `json:"otel,omitempty" yaml:"otel,omitempty" config:"otel,omitempty"`
		} `json:"features" yaml:"features" config:"features"`
	} `json:"agent" yaml:"agent" config:"agent"`
}

// SetExecutionModeFromConfig sets the execution mode of the OTel runtime based on the config.
func SetExecutionModeFromConfig(log *logp.Logger, conf *config.Config) {
	var c execModeConfig
	if err := conf.UnpackTo(&c); err != nil {
		log.Warnf("failed to unpack config in otel init execution mode: %v", err)
		return
	}

	if c.Agent.Features.Otel != nil && c.Agent.Features.Otel.SubprocessExecution {
		executionMode = manager.SubprocessExecutionMode
	} else {
		executionMode = manager.EmbeddedExecutionMode
	}
}

// GetExecutionMode returns the execution mode of the OTel runtime.
func GetExecutionMode() manager.ExecutionMode {
	return executionMode
}

// IsSubprocessExecution returns true if the OTel runtime is running in subprocess mode.
func IsSubprocessExecution() bool {
	return executionMode == manager.SubprocessExecutionMode
}
